#include "bro_json_db.h"

#ifndef BIGBRO_H_238764238764
#define BIGBRO_H_238764238764

namespace bro
{
	enum DATABASE_HOST : uint8_t
		{	DATABASE_HOST_LOCAL		= 0
		,	DATABASE_HOST_REMOTE
		};

	struct SJSONDatabase {
		::gpk::SJSONFile														Table						= {};
		::gpk::array_obj<::gpk::view_const_string>								Bindings					= {};
		::gpk::SRange<uint64_t>													Range						= {0, (uint64_t)-1LL};
		::bro::DATABASE_HOST													HostType					= ::bro::DATABASE_HOST_LOCAL;
	};

	typedef ::gpk::SKeyVal<::gpk::view_const_string, ::bro::SJSONDatabase>	TKeyValJSONDB;
	struct SBigBro {
		::gpk::array_obj<::bro::TKeyValJSONDB>									Databases							= {};
	};
	
	::gpk::error_t															loadConfig							(::bro::SBigBro & appState, const ::gpk::SJSONReader & configReader, int32_t indexBigBroNode = -1);
} // namespace

#endif // BIGBRO_H_238764238764
