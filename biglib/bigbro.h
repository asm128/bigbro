#include "bro_json_db.h"

#ifndef BIGBRO_H_238764238764
#define BIGBRO_H_238764238764

namespace bro
{
	struct SBigBroV0 {
		::gpk::array_obj<::bro::TKeyValJSONDBV0>		Databases							= {};
		::bro::SQuery									Query								= {};
		::gpk::SJSONFile								JSONConfig							= {};
	};
	
	::gpk::error_t									configLoad							(::bro::SBigBroV0 & appState, const ::gpk::SJSONReader & configReader, const ::gpk::view_array<const ::gpk::view_const_string> & databasesToLoad = {}, int32_t indexAppNode = -1);
	::gpk::error_t									queryLoad							(::bro::SQuery& query, const ::gpk::view_array<const ::gpk::TKeyValConstString> keyvals);
	::gpk::error_t									blockFileLoad						(::bro::TKeyValJSONDBV1 & jsonDB, uint32_t block);
	::gpk::error_t									blockFileName						(::gpk::array_pod<char_t> & filename, const ::gpk::view_const_string & dbName, const ::gpk::view_const_string & encryptionKey, const ::bro::DATABASE_HOST hostType, const uint32_t block);
	::gpk::error_t									tableFolderName						(::gpk::array_pod<char_t> & foldername, const ::gpk::view_const_string & dbName, const uint32_t block);
	::gpk::error_t									tableFileName						(::gpk::array_pod<char_t> & filename, const ::bro::DATABASE_HOST & hostType, const ::gpk::view_const_string & jsonDBKey);
} // namespace

#endif // BIGBRO_H_238764238764
