#include "bro_json_db.h"

#ifndef BIGBRO_H_238764238764
#define BIGBRO_H_238764238764

namespace bro
{
	struct SBigBro {
		::gpk::array_obj<::bro::TKeyValJSONDB>									Databases							= {};
	};
	
	::gpk::error_t															loadConfig							(::bro::SBigBro & appState, const ::gpk::SJSONReader & configReader, int32_t indexBigBroNode = -1);
} // namespace

#endif // BIGBRO_H_238764238764
