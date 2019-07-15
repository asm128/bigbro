#include "bro_json_db.h"

#ifndef BIGBRO_H_238764238764
#define BIGBRO_H_238764238764

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
	struct SBigBro {
		::gpk::array_obj<::bro::TKeyValJSONDB>									Databases					= {};
		::bro::SQuery															Query						= {};
		::gpk::array_pod<char_t>												CWD							= {};
		::gpk::SJSONFile														JSONConfig					= {};
	};
	
	::gpk::error_t															loadConfig					(::bro::SBigBro & appState, const ::gpk::SJSONReader & configReader, int32_t indexBigBroNode = -1);
	::gpk::error_t															loadQuery					(::bro::SQuery& query, const ::gpk::view_array<const ::gpk::TKeyValConstString> keyvals);
	::gpk::error_t															generate_output_for_db		(::bro::SBigBro & app, const ::gpk::view_const_string & databaseName, int32_t detail, ::gpk::array_pod<char_t> & output);
} // namespace

#endif // BIGBRO_H_238764238764
