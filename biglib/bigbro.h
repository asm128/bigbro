#include "bro_json_db.h"

#ifndef BIGBRO_H_238764238764
#define BIGBRO_H_238764238764

namespace bro
{
	struct SBigBroV0 {
		::llc::array_obj<::bro::TKeyValJSONDBV0>		Databases							= {};
		::bro::SQuery									Query								= {};
		::llc::SJSONFile								JSONConfig							= {};
	};
	
	::llc::error_t									configLoad							(::bro::SBigBroV0 & appState, const ::llc::SJSONReader & configReader, const ::llc::view_array<const ::llc::view_const_string> & databasesToLoad = {}, int32_t indexAppNode = -1);
	::llc::error_t									queryLoad							(::bro::SQuery& query, const ::llc::view_array<const ::llc::TKeyValConstString> keyvals);
	::llc::error_t									blockFileLoad						(::bro::TKeyValJSONDBV1 & jsonDB, uint32_t block);
	::llc::error_t									blockFileName						(::llc::array_pod<char_t> & filename, const ::llc::view_const_string & dbName, const ::llc::view_const_string & encryptionKey, const ::bro::DATABASE_HOST hostType, const uint32_t block);
	::llc::error_t									tableFolderName						(::llc::array_pod<char_t> & foldername, const ::llc::view_const_string & dbName, const uint32_t block);
	::llc::error_t									tableFileName						(::llc::array_pod<char_t> & filename, const ::bro::DATABASE_HOST & hostType, const ::llc::view_const_string & jsonDBKey);
} // namespace

#endif // BIGBRO_H_238764238764
