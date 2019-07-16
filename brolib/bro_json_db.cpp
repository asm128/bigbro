#include "bro_json_db.h"

#include "gpk_stdstring.h"
#include "gpk_find.h"

static	::gpk::error_t							generate_record_with_expansion			(const ::gpk::view_array<const ::bro::TKeyValJSONDB> & databases, const ::gpk::SJSONReader & databaseReader, uint32_t iRecord, ::gpk::array_pod<char_t> & output, ::gpk::array_obj<::gpk::SKeyVal<::gpk::view_const_string, int64_t>> & cacheMisses, const ::gpk::view_array<const ::gpk::view_const_string> & fieldsToExpand)	{
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
					if(indexRecordToExpandRelative < 0 || 0 == childDatabase.Val.Table.Reader.Tree.size()) {
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
					cacheMisses.push_back({fieldToExpand, (int64_t)indexRecordToExpand});
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

::gpk::error_t									bro::generate_output_for_db				
	( const ::gpk::view_array<const ::bro::TKeyValJSONDB>						& databases
	, const ::bro::SQuery														& query
	, const ::gpk::view_const_string											& databaseName
	, int32_t																	detail
	, ::gpk::array_pod<char_t>													& output
	, ::gpk::array_obj<::gpk::SKeyVal<::gpk::view_const_string, int64_t>>		& cacheMisses
	)
{
	int32_t												indexDB									= ::gpk::find(databaseName, ::gpk::view_array<const ::gpk::SKeyVal<::gpk::view_const_string, ::bro::SJSONDatabase>>{databases.begin(), databases.size()});
	rew_if(-1 == indexDB, "Database not found : %s", databaseName.begin());
	const ::gpk::SJSONReader							& dbReader								= databases[indexDB].Val.Table.Reader;
	const ::gpk::SJSONNode								& jsonRoot								= *databases[indexDB].Val.Table.Reader.Tree[0];
	int32_t												partialMiss								= 0;
	if(detail != -1) { // display detail
		if(0 == query.Expand.size() && ((uint32_t)detail) >= jsonRoot.Children.size())
			::gpk::jsonWrite(&jsonRoot, dbReader.View, output);
		else {
			if(0 == query.Expand.size()) 
				::gpk::jsonWrite(jsonRoot.Children[detail], dbReader.View, output);
			else {
				::gpk::array_obj<::gpk::view_const_string>			fieldsToExpand;
				::gpk::split(query.Expand, '.', fieldsToExpand);
				partialMiss										+= ::generate_record_with_expansion(databases, databases[indexDB].Val.Table.Reader, jsonRoot.Children[detail]->ObjectIndex, output, cacheMisses, fieldsToExpand);
			}
		}
	}
	else {  // display multiple records
		if(0 == query.Expand.size() && 0 >= query.Range.Offset && query.Range.Count >= jsonRoot.Children.size())
			::gpk::jsonWrite(&jsonRoot, dbReader.View, output);
		else {
			output.push_back('[');
			const uint32_t										stopRecord								= (uint32_t)::gpk::min(query.Range.Offset + query.Range.Count, (uint64_t)jsonRoot.Children.size());
			if(0 == query.Expand.size()) {
				for(uint32_t iRecord = (uint32_t)query.Range.Offset; iRecord < stopRecord; ++iRecord) {
					::gpk::jsonWrite(jsonRoot.Children[iRecord], dbReader.View, output);
					if((stopRecord - 1) > iRecord)
						output.push_back(',');
				}
			}
			else {
				::gpk::array_obj<::gpk::view_const_string>			fieldsToExpand;
				::gpk::split(query.Expand, '.', fieldsToExpand);
				for(uint32_t iRecord = (uint32_t)query.Range.Offset; iRecord < stopRecord; ++iRecord) {
					partialMiss										+= ::generate_record_with_expansion(databases, databases[indexDB].Val.Table.Reader, jsonRoot.Children[iRecord]->ObjectIndex, output, cacheMisses, fieldsToExpand);
					if((stopRecord - 1) > iRecord)
						output.push_back(',');
				}
			}
			output.push_back(']');
		}
	}
	return partialMiss;
}
