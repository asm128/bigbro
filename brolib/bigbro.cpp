#include "bigbro.h"

#include "gpk_json_expression.h"

#include "gpk_stdstring.h"
#include "gpk_find.h"

::gpk::error_t									bro::loadQuery							(::bro::SQuery& query, const ::gpk::view_array<const ::gpk::TKeyValConstString> keyvals)	{
	::gpk::keyvalNumeric("offset"	, keyvals, query.Range.Offset	);
	::gpk::keyvalNumeric("limit"	, keyvals, query.Range.Count	);
	::gpk::error_t										indexExpand								= ::gpk::find("expand", keyvals);
	if(-1 != indexExpand) 
		query.Expand									= keyvals[indexExpand].Val;
	return 0;
}

::gpk::error_t									bro::loadConfig				(::bro::SBigBro & appState, const ::gpk::SJSONReader & configReader, int32_t indexBigBroNode)	{
	::gpk::view_const_string							jsonResult					= {};
	const int32_t										indexObjectDatabases		= (-1 == indexBigBroNode) 
		? ::gpk::jsonExpressionResolve("application.bigbro.databases", configReader, 0, jsonResult) 
		: ::gpk::jsonExpressionResolve("databases", configReader, indexBigBroNode, jsonResult) 
		;
	gpk_necall(indexObjectDatabases, "%s", "Failed to get database config from JSON file.");
	jsonResult										= "";
	const ::gpk::error_t								databaseArraySize			= ::gpk::jsonArraySize(*configReader[indexObjectDatabases]);
	gpk_necall(databaseArraySize, "%s", "Failed to get database count from config file.");
	char												temp[64];
	appState.Databases.resize(databaseArraySize);
	for(uint32_t iDatabase = 0, countDatabases = (uint32_t)databaseArraySize; iDatabase < countDatabases; ++iDatabase) {
		sprintf_s(temp, "[%u].name", iDatabase);
		gpk_necall(::gpk::jsonExpressionResolve(temp, configReader, indexObjectDatabases, jsonResult), "Failed to load config from json! Last contents found: %s.", jsonResult.begin());
		::bro::TKeyValJSONDB								& jsonDB					= appState.Databases[iDatabase];
		jsonDB.Key										= jsonResult;

		sprintf_s(temp, "[%u].type", iDatabase);
		jsonResult										= {};
		int32_t												typeFound					= ::gpk::jsonExpressionResolve(temp, configReader, indexObjectDatabases, jsonResult);
		::gpk::array_pod<char_t>							dbfilename					= jsonDB.Key;
		dbfilename.append(".json");
		gwarn_if(errored(typeFound), "Failed to load database type for database: %s. Defaulting to local.", dbfilename.begin());
		jsonDB.Val.HostType												= (::gpk::view_const_string{"local"} == jsonResult || errored(typeFound)) ? ::bro::DATABASE_HOST_LOCAL : ::bro::DATABASE_HOST_REMOTE;
		// -- Load field bindings
		sprintf_s(temp, "[%u].bind", iDatabase);
		::gpk::error_t										indexBindArray				= ::gpk::jsonExpressionResolve(temp, configReader, indexObjectDatabases, jsonResult);
		w_if(errored(indexBindArray), "No bindings found for database file: %s.", dbfilename.begin())
		else {
			::gpk::error_t										sizeBindArray				= ::gpk::jsonArraySize(*configReader[indexBindArray]);
			jsonDB.Val.Bindings.resize(sizeBindArray);
			for(uint32_t iBind = 0; iBind < jsonDB.Val.Bindings.size(); ++iBind) {
				sprintf_s(temp, "[%u]", iBind);
				gpk_necall(::gpk::jsonExpressionResolve(temp, configReader, indexBindArray, jsonResult), "Failed to load config from json! Last contents found: %s.", jsonResult.begin());
				jsonDB.Val.Bindings[iBind]						= jsonResult;
			}
		}
		if(::bro::DATABASE_HOST_LOCAL != jsonDB.Val.HostType) 
			continue;
		// -- Load json database file.
		gpk_necall(::gpk::jsonFileRead(jsonDB.Val.Table, {dbfilename.begin(), dbfilename.size()}), "Failed to load database: %s.", dbfilename.begin());
	}
	return 0;
}

static	::gpk::error_t							generate_record_with_expansion			(::gpk::view_array<::bro::TKeyValJSONDB> & databases, const ::gpk::SJSONReader & databaseReader, uint32_t iRecord, ::gpk::array_pod<char_t> & output, ::gpk::array_pod<int32_t> & cacheMisses, const ::gpk::view_array<const ::gpk::view_const_string> & fieldsToExpand)	{
	const ::gpk::SJSONNode								& node									= *databaseReader.Tree[iRecord];
	int32_t												partialMiss								= 0;
	if(0 == fieldsToExpand.size() || ::gpk::JSON_TYPE_OBJECT != node.Object->Type)
		::gpk::jsonWrite(&node, databaseReader.View, output);
	else {
		output.push_back('{');
		for(uint32_t iChild = 0; iChild < node.Children.size(); iChild += 2) { 
			uint32_t											indexKey								= node.Children[iChild + 0]->ObjectIndex;
			uint32_t											indexVal								= node.Children[iChild + 1]->ObjectIndex;
			const ::gpk::view_const_string						fieldToExpand							= fieldsToExpand[0];
			const bool											bExpand									= databaseReader.View[indexKey] == fieldToExpand && ::gpk::JSON_TYPE_NULL != databaseReader.Tree[indexVal]->Object->Type;
			if(false == bExpand)  {
				::gpk::jsonWrite(databaseReader.Tree[indexKey], databaseReader.View, output);
				output.push_back(':');
				::gpk::jsonWrite(databaseReader.Tree[indexVal], databaseReader.View, output);
			}
			else {
				::gpk::jsonWrite(databaseReader.Tree[indexKey], databaseReader.View, output);
				output.push_back(':');
				bool												bSolved									= false;
				uint64_t											indexRecordToExpand						= 0;
				::gpk::stoull(databaseReader.View[indexVal], &indexRecordToExpand);
				for(uint32_t iDatabase = 0; iDatabase < databases.size(); ++iDatabase) {
					const ::bro::TKeyValJSONDB							& childDatabase							= databases[iDatabase];
					int64_t												indexRecordToExpandRelative				= (int64_t)indexRecordToExpand - childDatabase.Val.Range.Offset;
					if(indexRecordToExpandRelative < 0) {
						info_printf("Out of range - requires reload or probably there is another database with this info.");
						continue;
					}
					bool												bAliasMatch								= -1 != ::gpk::find(fieldToExpand, {childDatabase.Val.Bindings.begin(), childDatabase.Val.Bindings.size()});
					if(childDatabase.Key == fieldToExpand || bAliasMatch) {
						const ::gpk::SJSONNode								& childRoot								= *childDatabase.Val.Table.Reader.Tree[0];
						if(indexRecordToExpandRelative >= childRoot.Children.size()) {
							info_printf("Out of range - requires reload or probably there is another database with this info.");
							continue;
						}
						if(1 >= fieldsToExpand.size()) {
							if(indexRecordToExpandRelative < childRoot.Children.size())
								::gpk::jsonWrite(childRoot.Children[(uint32_t)indexRecordToExpandRelative], childDatabase.Val.Table.Reader.View, output);
							else
								::gpk::jsonWrite(databaseReader.Tree[indexVal], databaseReader.View, output);
						}
						else {
							if(indexRecordToExpandRelative < childRoot.Children.size())
								::generate_record_with_expansion(databases, childDatabase.Val.Table.Reader, childRoot.Children[(uint32_t)indexRecordToExpandRelative]->ObjectIndex, output, cacheMisses, {&fieldsToExpand[1], fieldsToExpand.size()-1});
							else
								::gpk::jsonWrite(databaseReader.Tree[indexVal], databaseReader.View, output);
						}
						bSolved											= true;
					}
				}
				if(false == bSolved) {
					cacheMisses.push_back(output.size());
					::gpk::jsonWrite(databaseReader.Tree[indexVal], databaseReader.View, output);
					++partialMiss;
				}
			}
			if((node.Children.size() - 2) > iChild)
				output.push_back(',');
		}
		output.push_back('}');
	}
	return partialMiss;
}

::gpk::error_t									bro::generate_output_for_db				(::bro::SBigBro & app, const ::gpk::view_const_string & databaseName, int32_t detail, ::gpk::array_pod<char_t> & output, ::gpk::array_pod<int32_t> & cacheMisses)					{
	int32_t												indexDB									= ::gpk::find(databaseName, ::gpk::view_array<const ::gpk::SKeyVal<::gpk::view_const_string, ::bro::SJSONDatabase>>{app.Databases.begin(), app.Databases.size()});
	rew_if(-1 == indexDB, "Database not found : %s", databaseName.begin());
	::gpk::SJSONReader									& dbReader								= app.Databases[indexDB].Val.Table.Reader;
	::gpk::SJSONNode									& jsonRoot								= *app.Databases[indexDB].Val.Table.Reader.Tree[0];
	int32_t												partialMiss								= 0;
	if(detail != -1) { // display detail
		if(0 == app.Query.Expand.size() && ((uint32_t)detail) >= jsonRoot.Children.size())
			::gpk::jsonWrite(&jsonRoot, dbReader.View, output);
		else {
			if(0 == app.Query.Expand.size()) 
				::gpk::jsonWrite(jsonRoot.Children[detail], dbReader.View, output);
			else {
				::gpk::array_obj<::gpk::view_const_string>			fieldsToExpand;
				::gpk::split(app.Query.Expand, '.', fieldsToExpand);
				partialMiss										+= ::generate_record_with_expansion(app.Databases, app.Databases[indexDB].Val.Table.Reader, jsonRoot.Children[detail]->ObjectIndex, output, cacheMisses, fieldsToExpand);
			}
		}
	}
	else {  // display multiple records
		if(0 == app.Query.Expand.size() && 0 >= app.Query.Range.Offset && app.Query.Range.Count >= jsonRoot.Children.size())
			::gpk::jsonWrite(&jsonRoot, dbReader.View, output);
		else {
			output.push_back('[');
			const uint32_t										stopRecord								= (uint32_t)::gpk::min(app.Query.Range.Offset + app.Query.Range.Count, (uint64_t)jsonRoot.Children.size());
			if(0 == app.Query.Expand.size()) {
				for(uint32_t iRecord = (uint32_t)app.Query.Range.Offset; iRecord < stopRecord; ++iRecord) {
					::gpk::jsonWrite(jsonRoot.Children[iRecord], dbReader.View, output);
					if((stopRecord - 1) > iRecord)
						output.push_back(',');
				}
			}
			else {
				::gpk::array_obj<::gpk::view_const_string>			fieldsToExpand;
				::gpk::split(app.Query.Expand, '.', fieldsToExpand);
				for(uint32_t iRecord = (uint32_t)app.Query.Range.Offset; iRecord < stopRecord; ++iRecord) {
					partialMiss										+= ::generate_record_with_expansion(app.Databases, app.Databases[indexDB].Val.Table.Reader, jsonRoot.Children[iRecord]->ObjectIndex, output, cacheMisses, fieldsToExpand);
					if((stopRecord - 1) > iRecord)
						output.push_back(',');
				}
			}
			output.push_back(']');
		}
	}
	return partialMiss;
}
