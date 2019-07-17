#include "gpk_json.h"

#ifndef BRO_JSON_DB_H_029430293742
#define BRO_JSON_DB_H_029430293742

namespace bro
{
	GDEFINE_ENUM_TYPE (DATABASE_HOST, int8_t);
	GDEFINE_ENUM_VALUE(DATABASE_HOST, LOCAL				, 0);
	GDEFINE_ENUM_VALUE(DATABASE_HOST, REMOTE			, 1);
	GDEFINE_ENUM_VALUE(DATABASE_HOST, DEFLATE			, 2);
	GDEFINE_ENUM_VALUE(DATABASE_HOST, REMOTE_DEFLATE	, 3);

	static constexpr	const uint64_t										MAX_TABLE_RECORD_COUNT		= 0x7FFFFFFFFFFFFFFF;

	struct SJSONDatabaseV0 {
		::gpk::array_obj<::gpk::view_const_string>									Bindings					= {};
		::gpk::SRange<uint64_t>														Range						= {0, MAX_TABLE_RECORD_COUNT};
		uint64_t																	BlockSize					= 0;
		::bro::DATABASE_HOST														HostType					= ::bro::DATABASE_HOST_LOCAL;
		::gpk::SJSONFile															Table						= {};
		::gpk::array_obj<::gpk::SJSONFile>											Blocks						= {};
	};

	struct SJSONDatabaseV1 {
		::gpk::array_obj<::gpk::view_const_string>									Bindings					= {};
		uint64_t																	BlockSize					= 0;
		::gpk::SJSONFile															Table						= {};
		::gpk::array_obj<::gpk::SJSONFile>											Blocks						= {};
		::gpk::array_obj<uint64_t>													BlockOffsets				= {};
		::bro::DATABASE_HOST														HostType					= ::bro::DATABASE_HOST_LOCAL;
	};

	struct SQuery {
		::gpk::SRange<uint64_t>														Range						= {0, MAX_TABLE_RECORD_COUNT};
		int64_t																		Detail						= -1;
		::gpk::view_const_string													Expand						= "";
	};

	typedef ::gpk::SKeyVal<::gpk::view_const_string, ::gpk::array_pod<int64_t>>	TCacheMissRecord;
	typedef ::gpk::SKeyVal<::gpk::view_const_string, ::bro::SJSONDatabaseV0>	TKeyValJSONDBV0;
	::gpk::error_t															generate_output_for_db				
		( const ::gpk::view_array<const ::bro::TKeyValJSONDBV0>	& databases
		, const ::bro::SQuery									& query
		, const ::gpk::view_const_string						& databaseName
		, ::gpk::array_pod<char_t>								& output
		, ::gpk::array_obj<TCacheMissRecord>					& cacheMisses
		);
}

#endif // BRO_JSON_DB_H_029430293742
