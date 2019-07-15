#include "bigbro.h"

#include "gpk_json_expression.h"

::gpk::error_t												bro::loadConfig				(::bro::SBigBro & appState, const ::gpk::SJSONReader & configReader, int32_t indexBigBroNode)	{
	::gpk::view_const_string										jsonResult					= {};
	const int32_t													indexObjectDatabases		= (-1 == indexBigBroNode) 
		? ::gpk::jsonExpressionResolve("application.bigbro.databases", configReader, 0, jsonResult) 
		: ::gpk::jsonExpressionResolve("databases", configReader, indexBigBroNode, jsonResult) 
		;
	gpk_necall(indexObjectDatabases, "%s", "Failed to get database config from JSON file.");
	jsonResult															= "";
	const ::gpk::error_t													databaseArraySize			= ::gpk::jsonArraySize(*configReader[indexObjectDatabases]);
	gpk_necall(databaseArraySize, "%s", "Failed to get database count from config file.");
	char																	temp[64];
	appState.Databases.resize(databaseArraySize);
	for(uint32_t iDatabase = 0, countDatabases = (uint32_t)databaseArraySize; iDatabase < countDatabases; ++iDatabase) {
		sprintf_s(temp, "[%u].name", iDatabase);
		gpk_necall(::gpk::jsonExpressionResolve(temp, configReader, indexObjectDatabases, jsonResult), "Failed to load config from json! Last contents found: %s.", jsonResult.begin());
		::bro::TKeyValJSONDB												& jsonDB						= appState.Databases[iDatabase];
		jsonDB.Key														= jsonResult;

		sprintf_s(temp, "[%u].type", iDatabase);
		gpk_necall(::gpk::jsonExpressionResolve(temp, configReader, indexObjectDatabases, jsonResult), "Failed to load config from json! Last contents found: %s.", jsonResult.begin());
		jsonDB.Val.HostType												= (jsonResult == "local") ? ::bro::DATABASE_HOST_REMOTE : ::bro::DATABASE_HOST_LOCAL;

		if(::bro::DATABASE_HOST_LOCAL == jsonDB.Val.HostType) {
			// Load json database file.
			::gpk::array_pod<char_t>											dbfilename						= jsonDB.Key;
			dbfilename.append(".json");
			gpk_necall(::gpk::jsonFileRead(jsonDB.Val.Table, {dbfilename.begin(), dbfilename.size()}), "Failed to load database: %s.", dbfilename.begin());
			// Load field bindings
			sprintf_s(temp, "[%u].bind", iDatabase);
			::gpk::error_t														indexBindArray					= ::gpk::jsonExpressionResolve(temp, configReader, indexObjectDatabases, jsonResult);
			cw_if(errored(indexBindArray), "No bindings found for database file: %s.", dbfilename.begin());
			::gpk::error_t														sizeBindArray					= ::gpk::jsonArraySize(*configReader[indexBindArray]);
			jsonDB.Val.Bindings.resize(sizeBindArray);
			for(uint32_t iBind = 0; iBind < jsonDB.Val.Bindings.size(); ++iBind) {
				sprintf_s(temp, "[%u]", iBind);
				gpk_necall(::gpk::jsonExpressionResolve(temp, configReader, indexBindArray, jsonResult), "Failed to load config from json! Last contents found: %s.", jsonResult.begin());
				jsonDB.Val.Bindings[iBind]										= jsonResult;
			}
		}
	}
	return 0;
}
