#include "bigbro.h"

#include "gpk_json_expression.h"
#include "gpk_parse.h"

::gpk::error_t									bro::loadQuery							(::bro::SQuery& query, const ::gpk::view_array<const ::gpk::TKeyValConstString> keyvals)	{
	::gpk::keyvalNumeric("offset"	, keyvals, query.Range.Offset	);
	::gpk::keyvalNumeric("limit"	, keyvals, query.Range.Count	);
	::gpk::error_t										indexExpand								= ::gpk::find("expand", keyvals);
	if(-1 != indexExpand) 
		query.Expand									= keyvals[indexExpand].Val;
	return 0;
}

::gpk::error_t									bro::loadConfig				(::bro::SBigBro & appState, const ::gpk::SJSONReader & configReader, int32_t indexBigBroNode)	{
	::gpk::view_const_string							jsonResult					= {};
	const int32_t										indexObjectDatabases		= (-1 == indexBigBroNode) 
		? ::gpk::jsonExpressionResolve("application.bigbro.databases", configReader, 0, jsonResult) 
		: ::gpk::jsonExpressionResolve("databases", configReader, indexBigBroNode, jsonResult) 
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
		::bro::TKeyValJSONDB								& jsonDB					= appState.Databases[iDatabase];
		jsonDB.Key										= jsonResult;
		{
			sprintf_s(temp, "[%u].block", iDatabase);
			int32_t												indexBlockNode				= ::gpk::jsonExpressionResolve(temp, configReader, indexObjectDatabases, jsonResult);
			gwarn_if(errored(indexBlockNode), "Failed to load config from json! Last contents found: %s.", jsonResult.begin()) 
			else {
				::gpk::parseIntegerDecimal(jsonResult, &(jsonDB.Val.BlockSize = 0));
			}
		}
		sprintf_s(temp, "[%u].type", iDatabase);
		jsonResult										= {};
		int32_t												typeFound					= ::gpk::jsonExpressionResolve(temp, configReader, indexObjectDatabases, jsonResult);
		::gpk::array_pod<char_t>							dbfilename					= jsonDB.Key;
		dbfilename.append(".json");
		gwarn_if(errored(typeFound), "Failed to load database type for database: %s. Defaulting to local.", dbfilename.begin());
		jsonDB.Val.HostType								= (::gpk::view_const_string{"local"} == jsonResult || errored(typeFound)) ? ::bro::DATABASE_HOST_LOCAL : ::bro::DATABASE_HOST_REMOTE;
		// -- Load field bindings
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
		if(::bro::DATABASE_HOST_LOCAL != jsonDB.Val.HostType) 
			continue;
		if(jsonDB.Val.BlockSize)
			continue;	// block databases get loaded on-demand
		// -- Load json database file.
		gpk_necall(::gpk::jsonFileRead(jsonDB.Val.Table, {dbfilename.begin(), dbfilename.size()}), "Failed to load database: %s.", dbfilename.begin());
	}
	return 0;
}
