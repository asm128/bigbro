#include "gpk_json.h"

#ifndef BRO_JSON_DB_H_029430293742
#define BRO_JSON_DB_H_029430293742

namespace bro
{
	enum DATABASE_HOST : uint8_t
		{	DATABASE_HOST_LOCAL		= 0
		,	DATABASE_HOST_REMOTE
		};

	static constexpr	const uint64_t										MAX_TABLE_RECORD_COUNT		= 0x7FFFFFFFFFFFFFFF;

	struct SJSONDatabase {
		::gpk::SJSONFile														Table						= {};
		::gpk::array_obj<::gpk::view_const_string>								Bindings					= {};
		::gpk::SRange<uint64_t>													Range						= {0, MAX_TABLE_RECORD_COUNT};
		::bro::DATABASE_HOST													HostType					= ::bro::DATABASE_HOST_LOCAL;
	};

	struct SQuery {
		::gpk::SRange<uint64_t>													Range						= {0, MAX_TABLE_RECORD_COUNT};
		::gpk::view_const_string												Expand						= "";
	};

	typedef ::gpk::SKeyVal<::gpk::view_const_string, ::bro::SJSONDatabase>	TKeyValJSONDB;
}

#endif // BRO_JSON_DB_H_029430293742
