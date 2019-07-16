#include "bro_json_db.h"

#ifndef BIGBRO_H_238764238764
#define BIGBRO_H_238764238764

namespace bro
{
	struct SBigBro {
		::gpk::array_obj<::bro::TKeyValJSONDB>		Databases							= {};
		::bro::SQuery								Query								= {};
		::gpk::array_pod<char_t>					CWD									= {};
		::gpk::SJSONFile							JSONConfig							= {};
	};
	
	::gpk::error_t								loadConfig							(::bro::SBigBro & appState, const ::gpk::SJSONReader & configReader, int32_t indexBigBroNode = -1);
	::gpk::error_t								loadQuery							(::bro::SQuery& query, const ::gpk::view_array<const ::gpk::TKeyValConstString> keyvals);
	::gpk::error_t								generate_output_for_db				(::bro::SBigBro & app, const ::gpk::view_const_string & databaseName, int32_t detail, ::gpk::array_pod<char_t> & output, ::gpk::array_pod<int32_t> & cacheMisses);
} // namespace

#endif // BIGBRO_H_238764238764
