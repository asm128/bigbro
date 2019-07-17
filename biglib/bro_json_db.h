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

	struct SJSONDatabaseV0 {
		::gpk::array_obj<::gpk::view_const_string>								Bindings					= {};
		::gpk::SRange<uint64_t>													Range						= {0, MAX_TABLE_RECORD_COUNT};
		uint64_t																BlockSize					= 0;
		::bro::DATABASE_HOST													HostType					= ::bro::DATABASE_HOST_LOCAL;
		::gpk::SJSONFile														Table						= {};
		::gpk::array_obj<::gpk::SJSONFile>										Blocks						= {};
	};

	struct SJSONDatabaseV1 {
		::gpk::array_obj<::gpk::view_const_string>								Bindings					= {};
		uint64_t																BlockSize					= 0;
		::bro::DATABASE_HOST													HostType					= ::bro::DATABASE_HOST_LOCAL;
		::gpk::SJSONFile														Table						= {};
		::gpk::array_obj<::gpk::SJSONFile>										Blocks						= {};
		::gpk::array_obj<::gpk::SRange<uint64_t>>								Ranges						= {};
	};

	struct SQuery {
		::gpk::SRange<uint64_t>													Range						= {0, MAX_TABLE_RECORD_COUNT};
		int64_t																	Detail						= -1;
		::gpk::view_const_string												Expand						= "";
	};

	typedef ::gpk::SKeyVal<::gpk::view_const_string, ::gpk::array_pod<int64_t>>	TCacheMissRecord;
	typedef ::gpk::SKeyVal<::gpk::view_const_string, ::bro::SJSONDatabaseV0>	TKeyValJSONDB;
	::gpk::error_t															generate_output_for_db				
		( const ::gpk::view_array<const ::bro::TKeyValJSONDB>	& databases
		, const ::bro::SQuery									& query
		, const ::gpk::view_const_string						& databaseName
		, ::gpk::array_pod<char_t>								& output
		, ::gpk::array_obj<TCacheMissRecord>					& cacheMisses
		);
}

#endif // BRO_JSON_DB_H_029430293742
