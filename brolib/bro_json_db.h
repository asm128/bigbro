#include "gpk_json.h"

#ifndef BRO_JSON_DB_H_029430293742
#define BRO_JSON_DB_H_029430293742

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
		::bro::DATABASE_HOST													HostType					= DATABASE_HOST_LOCAL;
	};

	typedef ::gpk::SKeyVal<::gpk::view_const_string, ::bro::SJSONDatabase>	TKeyValJSONDB;
}

#endif // BRO_JSON_DB_H_029430293742
