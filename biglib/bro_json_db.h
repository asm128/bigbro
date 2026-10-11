#include "llc_json.h"

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
		::llc::array_obj<::llc::view_const_string>									Bindings					= {};
		::llc::SRange<uint64_t>														Range						= {0, MAX_TABLE_RECORD_COUNT};
		uint64_t																	BlockSize					= 0;
		::bro::DATABASE_HOST														HostType					= ::bro::DATABASE_HOST_LOCAL;
		::llc::SJSONFile															Table						= {};
		::llc::array_obj<::llc::SJSONFile>											Blocks						= {};
	};

	struct SJSONDatabaseV1 {
		::llc::array_obj<::llc::view_const_string>									Bindings					= {};
		uint64_t																	BlockSize					= 0;
		::llc::array_obj<uint64_t>													BlockOffsets				= {};
		::llc::array_obj<::llc::SJSONFile>											Blocks						= {};
		::llc::SJSONFile															Table						= {};
		::llc::view_const_string													EncryptionKey				= {};
		::bro::DATABASE_HOST														HostType					= ::bro::DATABASE_HOST_LOCAL;
	};

	struct SQuery {
		::llc::SRange<uint64_t>														Range						= {0, MAX_TABLE_RECORD_COUNT};
		int64_t																		Detail						= -1;
		::llc::view_const_string													Expand						= "";
	};

	typedef ::llc::SKeyVal<::llc::view_const_string, ::llc::array_pod<int64_t>>	TCacheMissRecord;
	typedef ::llc::SKeyVal<::llc::view_const_string, ::bro::SJSONDatabaseV0>	TKeyValJSONDBV0;
	typedef ::llc::SKeyVal<::llc::view_const_string, ::bro::SJSONDatabaseV1>	TKeyValJSONDBV1;
	::llc::error_t															generate_output_for_db				
		( const ::llc::view_array<const ::bro::TKeyValJSONDBV0>	& databases
		, const ::bro::SQuery									& query
		, const ::llc::view_const_string						& databaseName
		, ::llc::array_pod<char_t>								& output
		, ::llc::array_obj<TCacheMissRecord>					& cacheMisses
		);
}

#endif // BRO_JSON_DB_H_029430293742
