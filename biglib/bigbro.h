#include "bro_json_db.h"

#ifndef BIGBRO_H_238764238764
#define BIGBRO_H_238764238764

namespace bro
{
	struct SBigBroV0 {
		::gpk::array_obj<::bro::TKeyValJSONDBV0>		Databases							= {};
		::bro::SQuery									Query								= {};
		::gpk::SJSONFile								JSONConfig							= {};
	};
	
	::gpk::error_t									loadConfig							(::bro::SBigBroV0 & appState, const ::gpk::SJSONReader & configReader, int32_t indexBigBroNode = -1);
	::gpk::error_t									loadQuery							(::bro::SQuery& query, const ::gpk::view_array<const ::gpk::TKeyValConstString> keyvals);
} // namespace

#endif // BIGBRO_H_238764238764
