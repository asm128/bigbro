#include "gpk_json.h"

#ifndef BIGBRO_H_238764238764
#define BIGBRO_H_238764238764

namespace bro
{
	struct SJSONDatabase {
		::gpk::SJSONFile														Table;
		::gpk::array_obj<::gpk::view_const_string>								Bindings;
	};

	typedef ::gpk::SKeyVal<::gpk::view_const_string, ::bro::SJSONDatabase>	TKeyValJSONDB;

	struct SBigBro {
		::gpk::array_obj<::bro::TKeyValJSONDB>									Databases							= {};
	};

	
	::gpk::error_t															loadConfig							(::bro::SBigBro & appState, const ::gpk::SJSONReader & configReader, int32_t indexBigBroNode = -1);

} // namespace

#endif // BIGBRO_H_238764238764
