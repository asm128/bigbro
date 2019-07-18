#include "bigbro.h"

#include "gpk_json_expression.h"
#include "gpk_parse.h"

::gpk::error_t									bro::loadQuery				(::bro::SQuery& query, const ::gpk::view_array<const ::gpk::TKeyValConstString> keyvals)	{
	::gpk::keyvalNumeric("offset"	, keyvals, query.Range.Offset	);
	::gpk::keyvalNumeric("limit"	, keyvals, query.Range.Count	);
	::gpk::error_t										indexExpand					= ::gpk::find("expand", keyvals);
	if(-1 != indexExpand) 
		query.Expand									= keyvals[indexExpand].Val;
	return 0;
}

::gpk::error_t									bro::blockFileName			(::gpk::array_pod<char_t> & filename, const ::bro::TKeyValJSONDBV1 & jsonDB, const uint32_t block) {
	filename										= jsonDB.Key;
	char												temp[64]					= {};
	const ::gpk::view_const_string						extension					= jsonDB.Val.EncryptionKey.size() 
		? ((::bro::DATABASE_HOST_DEFLATE & jsonDB.Val.HostType) ? "czsn" : "cjsn")
		: ((::bro::DATABASE_HOST_DEFLATE & jsonDB.Val.HostType) ? "zson" : "json")
		;
	sprintf_s(temp, ".%u.%s", block, extension.begin());
	filename.append(temp);
	return 0;
}

::gpk::error_t									bro::tableFileName			(::gpk::array_pod<char_t> & filename, const ::bro::TKeyValJSONDBV0 & jsonDB) {
	filename										= jsonDB.Key;
	char												temp[64]					= {};
	const ::gpk::view_const_string						extension					= (::bro::DATABASE_HOST_DEFLATE & jsonDB.Val.HostType) ? "zson" : "json";
	sprintf_s(temp, ".%s", extension.begin());
	filename.append(temp);
	return 0;
}

::gpk::error_t									bro::blockFileLoad			(::bro::TKeyValJSONDBV1 & jsonDB, uint32_t block)	{
	::gpk::array_pod<char_t>							fileName					= {};
	::bro::blockFileName(fileName, jsonDB, block);
	if(0 == jsonDB.Val.EncryptionKey.size()) {
		gpk_necall(::gpk::jsonFileRead(jsonDB.Val.Table, {fileName.begin(), fileName.size()}), "Failed to load database: %s.", fileName.begin());
	}
	else {
	
	}
	return 0;
}

::gpk::error_t									bro::loadConfig				(::bro::SBigBroV0 & appState, const ::gpk::SJSONReader & configReader, int32_t indexAppNode)	{
	::gpk::view_const_string							jsonResult					= {};
	const int32_t										indexObjectDatabases		= (-1 == indexAppNode) 
		? ::gpk::jsonExpressionResolve("application.bigbro.databases", configReader, 0, jsonResult) 
		: ::gpk::jsonExpressionResolve("databases", configReader, indexAppNode, jsonResult) 
		;
	gpk_necall(indexObjectDatabases, "%s", "Failed to get database config from JSON file.");
	jsonResult										= "";
	const ::gpk::error_t								databaseArraySize			= ::gpk::jsonArraySize(*configReader[indexObjectDatabases]);
	gpk_necall(databaseArraySize, "%s", "Failed to get database count from config file.");
	char												temp[64];
	appState.Databases.resize(databaseArraySize);
	for(uint32_t iDatabase = 0, countDatabases = (uint32_t)databaseArraySize; iDatabase < countDatabases; ++iDatabase) {
		sprintf_s(temp, "[%u].name", iDatabase);
		gpk_necall(::gpk::jsonExpressionResolve(temp, configReader, indexObjectDatabases, jsonResult), "Failed to load config from json! Last contents found: %s.", jsonResult.begin());
		::bro::TKeyValJSONDBV0								& jsonDB					= appState.Databases[iDatabase];
		jsonDB.Key										= jsonResult;
		{	// -- Load database block size
			sprintf_s(temp, "[%u].block", iDatabase);
			int32_t												indexBlockNode				= ::gpk::jsonExpressionResolve(temp, configReader, indexObjectDatabases, jsonResult);
			gwarn_if(errored(indexBlockNode), "Failed to load config from json! Last contents found: %s.", jsonResult.begin()) 
			else {
				::gpk::parseIntegerDecimal(jsonResult, &(jsonDB.Val.BlockSize = 0));
			}
		}
		::gpk::array_pod<char_t>							dbfilename					= {};
		::bro::tableFileName(dbfilename, jsonDB);
		{	// -- Load database modes (remote, deflate)
			sprintf_s(temp, "[%u].type", iDatabase);
			jsonResult										= {};
			int32_t												typeFound					= ::gpk::jsonExpressionResolve(temp, configReader, indexObjectDatabases, jsonResult);
			gwarn_if(errored(typeFound), "Failed to load database type for database: %s. Defaulting to local.", dbfilename.begin());
			jsonDB.Val.HostType								= (::gpk::view_const_string{"local"} == jsonResult || errored(typeFound)) ? ::bro::DATABASE_HOST_LOCAL : ::bro::DATABASE_HOST_REMOTE;
			sprintf_s(temp, "[%u].deflate", iDatabase);
			jsonResult										= {};
			typeFound										= ::gpk::jsonExpressionResolve(temp, configReader, indexObjectDatabases, jsonResult);
			gwarn_if(errored(typeFound), "Failed to load database compression for database: %s. Defaulting to uncompressed.", dbfilename.begin());
			if(::gpk::view_const_string{"true"} == jsonResult)
				jsonDB.Val.HostType								|= ::bro::DATABASE_HOST_DEFLATE;
		}
		{	// -- Load field bindings
			sprintf_s(temp, "[%u].bind", iDatabase);
			::gpk::error_t										indexBindArray				= ::gpk::jsonExpressionResolve(temp, configReader, indexObjectDatabases, jsonResult);
			w_if(errored(indexBindArray), "No bindings found for database file: %s.", dbfilename.begin())
			else {
				::gpk::error_t										sizeBindArray				= ::gpk::jsonArraySize(*configReader[indexBindArray]);
				jsonDB.Val.Bindings.resize(sizeBindArray);
				for(uint32_t iBind = 0; iBind < jsonDB.Val.Bindings.size(); ++iBind) {
					sprintf_s(temp, "[%u]", iBind);
					gpk_necall(::gpk::jsonExpressionResolve(temp, configReader, indexBindArray, jsonResult), "Failed to load config from json! Last contents found: %s.", jsonResult.begin());
					jsonDB.Val.Bindings[iBind]						= jsonResult;
				}
			}
		}
		if(::bro::DATABASE_HOST_LOCAL != jsonDB.Val.HostType) 
			continue;
		if(jsonDB.Val.BlockSize)
			continue;	// block databases get loaded on-demand
		// -- Load json database file.
		gpk_necall(::gpk::jsonFileRead(jsonDB.Val.Table, {dbfilename.begin(), dbfilename.size()}), "Failed to load database: %s.", dbfilename.begin());
	}
	return 0;
}
