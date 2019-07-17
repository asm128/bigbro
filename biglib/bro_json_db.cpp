#include "bro_json_db.h"

#include "gpk_stdstring.h"
#include "gpk_find.h"

static	::gpk::error_t							insertCacheMiss							(::gpk::array_obj<::bro::TCacheMissRecord> & cacheMisses, const ::gpk::view_const_string & field, const int64_t indexRecord)			{
	bool												bInserted								= false;
	for(uint32_t iAlias = 0; iAlias < cacheMisses.size(); ++iAlias) {
		::bro::TCacheMissRecord								& curMissRecord							= cacheMisses[iAlias];
		if(field != curMissRecord.Key)
			continue;
		for(uint32_t iMiss = 0; iMiss < curMissRecord.Val.size(); ++iMiss) {
			if(indexRecord == curMissRecord.Val[iMiss]) {
				bInserted										= true;
				break;
			}
			else if(curMissRecord.Val[iMiss] > indexRecord) {
				curMissRecord.Val.insert(iMiss, indexRecord);
				bInserted										= true;
				break;
			}
		}
		if(false == bInserted) {
			curMissRecord.Val.push_back(indexRecord);
			bInserted										= true;
			break;
		}
	}
	if(false == bInserted) 
		cacheMisses.push_back({field, {indexRecord, }});
	return 0;
}

static	::gpk::error_t							generate_record_with_expansion			(const ::gpk::view_array<const ::bro::TKeyValJSONDB> & databases, const ::gpk::SJSONReader & databaseReader, const ::gpk::SJSONNode	& databaseNode, ::gpk::array_pod<char_t> & output, ::gpk::array_obj<::bro::TCacheMissRecord> & cacheMisses, const ::gpk::view_array<const ::gpk::view_const_string> & fieldsToExpand, uint32_t indexFieldToExpand)	{
	//const ::gpk::SJSONNode								& node									= *databaseReader.Tree[iRecord];
	int32_t												partialMiss								= 0;
	if(0 == fieldsToExpand.size() || ::gpk::JSON_TYPE_OBJECT != databaseNode.Object->Type)
		::gpk::jsonWrite(&databaseNode, databaseReader.View, output);
	else {
		output.push_back('{');
		for(uint32_t iChild = 0; iChild < databaseNode.Children.size(); iChild += 2) { 
			uint32_t											indexKey								= databaseNode.Children[iChild + 0]->ObjectIndex;
			uint32_t											indexVal								= databaseNode.Children[iChild + 1]->ObjectIndex;
			const ::gpk::view_const_string						fieldToExpand							= fieldsToExpand[indexFieldToExpand];
			const bool											bExpand									= databaseReader.View[indexKey] == fieldToExpand && ::gpk::JSON_TYPE_NULL != databaseReader.Object[indexVal].Type;
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
					bool												bAliasMatch								= -1 != ::gpk::find(fieldToExpand, {childDatabase.Val.Bindings.begin(), childDatabase.Val.Bindings.size()});
					int64_t												indexRecordToExpandRelative				= (int64_t)indexRecordToExpand - childDatabase.Val.Range.Offset;
					const ::gpk::SJSONReader							& childReader							= childDatabase.Val.Table.Reader;
					if(0 == childReader.Tree.size()) // This database isn't loaded.
						continue;

					if(indexRecordToExpandRelative < 0) {
						info_printf("Out of range - requires reload or probably there is another database with this info.");
						continue;
					}
					if(childDatabase.Key == fieldToExpand || bAliasMatch) {
						const ::gpk::SJSONNode								& childRoot								= *childReader.Tree[0];
						if(indexRecordToExpandRelative >= childRoot.Children.size()) {
							info_printf("Out of range - requires reload or probably there is another database with this info.");
							continue;
						}
						if((indexFieldToExpand + 1) >= fieldsToExpand.size()) {
							if(indexRecordToExpandRelative < childRoot.Children.size())
								::gpk::jsonWrite(childRoot.Children[(uint32_t)indexRecordToExpandRelative], childReader.View, output);
							else
								::gpk::jsonWrite(databaseReader.Tree[indexVal], databaseReader.View, output);
						}
						else {
							if(indexRecordToExpandRelative < childRoot.Children.size()) {
								const int32_t									iRecordNode								= childRoot.Children[(uint32_t)indexRecordToExpandRelative]->ObjectIndex;
								::generate_record_with_expansion(databases, childReader, *childReader.Tree[iRecordNode], output, cacheMisses, fieldsToExpand, indexFieldToExpand + 1);
							}
							else
								::gpk::jsonWrite(databaseReader.Tree[indexVal], databaseReader.View, output);
						}
						bSolved											= true;
					}
				}
				if(false == bSolved) {
					::insertCacheMiss(cacheMisses, {fieldsToExpand[0].begin(), (uint32_t)(fieldsToExpand[indexFieldToExpand].end() - fieldsToExpand[0].begin())}, (int64_t)indexRecordToExpand);
					::gpk::jsonWrite(databaseReader.Tree[indexVal], databaseReader.View, output);
					++partialMiss;
				}
			}
			if((databaseNode.Children.size() - 2) > iChild)
				output.push_back(',');
		}
		output.push_back('}');
	}
	return partialMiss;
}

::gpk::error_t									bro::generate_output_for_db				
	( const ::gpk::view_array<const ::bro::TKeyValJSONDB>	& databases
	, const ::bro::SQuery									& query
	, const ::gpk::view_const_string						& databaseName
	, ::gpk::array_pod<char_t>								& output
	, ::gpk::array_obj<TCacheMissRecord>					& cacheMisses
	)
{
	int32_t												indexDB									= ::gpk::find(databaseName, ::gpk::view_array<const ::gpk::SKeyVal<::gpk::view_const_string, ::bro::SJSONDatabaseV0>>{databases.begin(), databases.size()});
	rew_if(-1 == indexDB, "Database not found : %s", databaseName.begin());
	::bro::TKeyValJSONDB								dbObject								= databases[indexDB];
	const ::gpk::SJSONReader							& dbReader								= dbObject.Val.Table.Reader;
	if(0 == dbReader.Tree.size()) {
		::insertCacheMiss(cacheMisses, databaseName, (int64_t)query.Detail);
		return 1;
	}
	const ::gpk::SJSONNode								& jsonRoot								= *dbReader.Tree[0];
	int32_t												partialMiss								= 0;
	int64_t												relativeDetail							= query.Detail - dbObject.Val.Range.Offset;
	if(query.Detail >= 0) { // display detail
		if(0 == query.Expand.size())
			::gpk::jsonWrite(&jsonRoot, dbReader.View, output);
		else if(relativeDetail < 0 || relativeDetail >= jsonRoot.Children.size()) {
			::insertCacheMiss(cacheMisses, databaseName, (int64_t)query.Detail);
			::gpk::jsonWrite(&jsonRoot, dbReader.View, output);
			return partialMiss								= 1;
		}
		else {
			if(0 == query.Expand.size()) 
				::gpk::jsonWrite(jsonRoot.Children[(uint32_t)relativeDetail], dbReader.View, output);
			else {
				::gpk::array_obj<::gpk::view_const_string>			fieldsToExpand;
				::gpk::split(query.Expand, '.', fieldsToExpand);
				const int32_t										iRecordNode								= jsonRoot.Children[(uint32_t)relativeDetail]->ObjectIndex;
				partialMiss										+= ::generate_record_with_expansion(databases, dbReader, *dbReader[iRecordNode], output, cacheMisses, fieldsToExpand, 0);
			}
		}
	}
	else {  // display multiple records
		if(0 == query.Expand.size() && 0 >= query.Range.Offset && query.Range.Count >= jsonRoot.Children.size())	// a larger range than available was requested and no expansion is required. Just send the whole thing
			::gpk::jsonWrite(&jsonRoot, dbReader.View, output);
		else {
			output.push_back('[');
			uint32_t											relativeQueryOffset						= (uint32_t)(query.Range.Offset - dbObject.Val.Range.Offset);
			const uint32_t										stopRecord								= (uint32_t)::gpk::min(relativeQueryOffset + query.Range.Count, (uint64_t)jsonRoot.Children.size());
			if(0 == query.Expand.size()) {
				for(uint32_t iRecord = relativeQueryOffset; iRecord < stopRecord; ++iRecord) {
					::gpk::jsonWrite(jsonRoot.Children[iRecord], dbReader.View, output);
					if((stopRecord - 1) > iRecord)
						output.push_back(',');
				}
			}
			else {
				::gpk::array_obj<::gpk::view_const_string>			fieldsToExpand;
				::gpk::split(query.Expand, '.', fieldsToExpand);
				for(uint32_t iRecord = (uint32_t)query.Range.Offset; iRecord < stopRecord; ++iRecord) {
					const int32_t										iRecordNode								= jsonRoot.Children[iRecord]->ObjectIndex;
					partialMiss										+= ::generate_record_with_expansion(databases, dbReader, *dbReader[iRecordNode], output, cacheMisses, fieldsToExpand, 0);
					if((stopRecord - 1) > iRecord)
						output.push_back(',');
				}
			}
			output.push_back(']');
		}
	}
	return partialMiss;
}
