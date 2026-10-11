#include "bro_json_db.h"

#include "llc_stdstring.h"
#include "llc_find.h"

static	::llc::error_t							insertCacheMiss							(::llc::array_obj<::bro::TCacheMissRecord> & cacheMisses, const ::llc::view_const_string & field, const int64_t indexRecord)			{
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

static	::llc::error_t							generate_record_with_expansion			(const ::llc::view_array<const ::bro::TKeyValJSONDBV0> & databases, const ::llc::SJSONReader & databaseReader, const ::llc::SJSONNode	& databaseNode, ::llc::array_pod<char_t> & output, ::llc::array_obj<::bro::TCacheMissRecord> & cacheMisses, const ::llc::view_array<const ::llc::view_const_string> & fieldsToExpand, uint32_t indexFieldToExpand)	{
	//const ::llc::SJSONNode								& node									= *databaseReader.Tree[iRecord];
	int32_t												partialMiss								= 0;
	if(0 == fieldsToExpand.size() || ::llc::JSON_TYPE_OBJECT != databaseNode.Object->Type)
		::llc::jsonWrite(&databaseNode, databaseReader.View, output);
	else {
		output.push_back('{');
		for(uint32_t iChild = 0; iChild < databaseNode.Children.size(); iChild += 2) { 
			uint32_t											indexKey								= databaseNode.Children[iChild + 0]->ObjectIndex;
			uint32_t											indexVal								= databaseNode.Children[iChild + 1]->ObjectIndex;
			const ::llc::view_const_string						fieldToExpand							= fieldsToExpand[indexFieldToExpand];
			const bool											bExpand									= databaseReader.View[indexKey] == fieldToExpand && ::llc::JSON_TYPE_NULL != databaseReader.Object[indexVal].Type;
			if(false == bExpand)  {
				::llc::jsonWrite(databaseReader.Tree[indexKey], databaseReader.View, output);
				output.push_back(':');
				::llc::jsonWrite(databaseReader.Tree[indexVal], databaseReader.View, output);
			}
			else {
				::llc::jsonWrite(databaseReader.Tree[indexKey], databaseReader.View, output);
				output.push_back(':');
				bool												bSolved									= false;
				uint64_t											indexRecordToExpand						= 0;
				::llc::stoull(databaseReader.View[indexVal], &indexRecordToExpand);
				for(uint32_t iDatabase = 0; iDatabase < databases.size(); ++iDatabase) {
					const ::bro::TKeyValJSONDBV0							& childDatabase							= databases[iDatabase];
					bool												bAliasMatch								= -1 != ::llc::find(fieldToExpand, {childDatabase.Val.Bindings.begin(), childDatabase.Val.Bindings.size()});
					int64_t												indexRecordToExpandRelative				= (int64_t)indexRecordToExpand - childDatabase.Val.Range.Offset;
					const ::llc::SJSONReader							& childReader							= childDatabase.Val.Table.Reader;
					if(0 == childReader.Tree.size()) // This database isn't loaded.
						continue;

					if(indexRecordToExpandRelative < 0) {
						info_printf("Out of range - requires reload or probably there is another database with this info.");
						continue;
					}
					if(childDatabase.Key == fieldToExpand || bAliasMatch) {
						const ::llc::SJSONNode								& childRoot								= *childReader.Tree[0];
						if(indexRecordToExpandRelative >= childRoot.Children.size()) {
							info_printf("Out of range - requires reload or probably there is another database with this info.");
							continue;
						}
						if((indexFieldToExpand + 1) >= fieldsToExpand.size()) {
							if(indexRecordToExpandRelative < childRoot.Children.size())
								::llc::jsonWrite(childRoot.Children[(uint32_t)indexRecordToExpandRelative], childReader.View, output);
							else
								::llc::jsonWrite(databaseReader.Tree[indexVal], databaseReader.View, output);
						}
						else {
							if(indexRecordToExpandRelative < childRoot.Children.size()) {
								const int32_t									iRecordNode								= childRoot.Children[(uint32_t)indexRecordToExpandRelative]->ObjectIndex;
								::generate_record_with_expansion(databases, childReader, *childReader.Tree[iRecordNode], output, cacheMisses, fieldsToExpand, indexFieldToExpand + 1);
							}
							else
								::llc::jsonWrite(databaseReader.Tree[indexVal], databaseReader.View, output);
						}
						bSolved											= true;
					}
				}
				if(false == bSolved) {
					::insertCacheMiss(cacheMisses, {fieldsToExpand[0].begin(), (uint32_t)(fieldsToExpand[indexFieldToExpand].end() - fieldsToExpand[0].begin())}, (int64_t)indexRecordToExpand);
					::llc::jsonWrite(databaseReader.Tree[indexVal], databaseReader.View, output);
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

::llc::error_t									bro::generate_output_for_db				
	( const ::llc::view_array<const ::bro::TKeyValJSONDBV0>	& databases
	, const ::bro::SQuery									& query
	, const ::llc::view_const_string						& databaseName
	, ::llc::array_pod<char_t>								& output
	, ::llc::array_obj<TCacheMissRecord>					& cacheMisses
	)
{
	int32_t												indexDB									= ::llc::find(databaseName, ::llc::view_array<const ::llc::SKeyVal<::llc::view_const_string, ::bro::SJSONDatabaseV0>>{databases.begin(), databases.size()});
	rew_if(-1 == indexDB, "Database not found : %s", databaseName.begin());
	::bro::TKeyValJSONDBV0								dbObject								= databases[indexDB];
	const ::llc::SJSONReader							& dbReader								= dbObject.Val.Table.Reader;
	if(0 == dbReader.Tree.size()) {
		::insertCacheMiss(cacheMisses, databaseName, (int64_t)query.Detail);
 		return 1;
	}
	const ::llc::SJSONNode								& jsonRoot								= *dbReader.Tree[0];
	int32_t												partialMiss								= 0;
	int64_t												relativeDetail							= query.Detail - dbObject.Val.Range.Offset;
	if(query.Detail >= 0) { // display detail
		if(0 == query.Expand.size())
			::llc::jsonWrite(jsonRoot.Children[(uint32_t)relativeDetail], dbReader.View, output);
		else if(relativeDetail < 0 || relativeDetail >= jsonRoot.Children.size()) {
			::insertCacheMiss(cacheMisses, databaseName, (int64_t)query.Detail);
			::llc::jsonWrite(&jsonRoot, dbReader.View, output);
			return partialMiss								= 1;
		}
		else {
			if(0 == query.Expand.size()) 
				::llc::jsonWrite(jsonRoot.Children[(uint32_t)relativeDetail], dbReader.View, output);
			else {
				::llc::array_obj<::llc::view_const_string>			fieldsToExpand;
				::llc::split(query.Expand, '.', fieldsToExpand);
				const int32_t										iRecordNode								= jsonRoot.Children[(uint32_t)relativeDetail]->ObjectIndex;
				partialMiss										+= ::generate_record_with_expansion(databases, dbReader, *dbReader[iRecordNode], output, cacheMisses, fieldsToExpand, 0);
			}
		}
	}
	else {  // display multiple records
		if(0 == query.Expand.size() && 0 >= query.Range.Offset && query.Range.Count >= jsonRoot.Children.size())	// a larger range than available was requested and no expansion is required. Just send the whole thing
			::llc::jsonWrite(&jsonRoot, dbReader.View, output);
		else {
			output.push_back('[');
			uint32_t											relativeQueryOffset						= (uint32_t)(query.Range.Offset - dbObject.Val.Range.Offset);
			const uint32_t										stopRecord								= (uint32_t)::llc::min(relativeQueryOffset + query.Range.Count, (uint64_t)jsonRoot.Children.size());
			if(0 == query.Expand.size()) {
				for(uint32_t iRecord = relativeQueryOffset; iRecord < stopRecord; ++iRecord) {
					::llc::jsonWrite(jsonRoot.Children[iRecord], dbReader.View, output);
					if((stopRecord - 1) > iRecord)
						output.push_back(',');
				}
			}
			else {
				::llc::array_obj<::llc::view_const_string>			fieldsToExpand;
				::llc::split(query.Expand, '.', fieldsToExpand);
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
