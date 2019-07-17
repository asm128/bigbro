#include "razor.h"

#include "gpk_stdstring.h"
#include "gpk_process.h"
#include "gpk_storage.h"

#include "gpk_json_expression.h"

static	::gpk::error_t					loadDetail					(const ::gpk::view_array<::gpk::TKeyValConstString> & queryString, int64_t & detail)				{
	for(uint32_t iKey = 0; iKey < queryString.size(); ++iKey) {
		if(queryString[iKey].Key == ::gpk::view_const_string{"PATH_INFO"}) {
			uint64_t									_detail						= (uint64_t)-1LL;
			::gpk::stoull({&queryString[iKey].Val[1], queryString[iKey].Val.size() - 1}, &_detail);
			detail									= (int32_t)_detail;
		}
	}
	return 0;
}

::gpk::error_t							razor::loadConfig			(::razor::SRazorAppV0 & appState, const ::gpk::view_array<::gpk::TKeyValConstString> & queryString)	{
	gpk_necall(::gpk::jsonFileRead(appState.Config, "razor.json"), "Failed to load configuration file: %s.", "razor.json");
	gpk_necall(::bro::loadConfig(appState.BigBro, appState.Config.Reader), "%s", "Failed to load query.");
	gpk_necall(::bro::loadQuery(appState.BigBro.Query, queryString), "%s", "Failed to load query.");
	gpk_necall(::loadDetail(queryString, appState.BigBro.Query.Detail), "%s", "Failed to load query.");
	return 0;
}

::gpk::error_t							processThisTable			(const ::gpk::view_const_string & missPath, const ::gpk::view_array<const ::bro::TKeyValJSONDBV0>	& databases, ::gpk::view_const_string & tableName)	{
	::gpk::array_obj<::gpk::view_const_string>	fieldsToExpand;
	::gpk::split(missPath, '.', fieldsToExpand);
	const ::gpk::view_const_string				fieldToExpand				= fieldsToExpand[fieldsToExpand.size() - 1];
	for(uint32_t iTable = 0; iTable < databases.size(); ++iTable) {
		const ::bro::TKeyValJSONDBV0					& dbKeyVal					= databases[iTable];
		if(dbKeyVal.Key == fieldToExpand) {
			tableName								= dbKeyVal.Key;
			return iTable;
		}
		for(uint32_t iAlias = 0; iAlias < dbKeyVal.Val.Bindings.size(); ++iAlias) {
			if(dbKeyVal.Val.Bindings[iAlias] == fieldToExpand) {
				tableName								= dbKeyVal.Key;
				return iTable;
			}
		}
	}
	return -1;
}

::gpk::error_t							razor::processQuery						
	( ::gpk::array_obj<::bro::TKeyValJSONDBV0>	& databases
	, const ::bro::SQuery						& query
	, const ::gpk::view_const_string			& databaseName
	, ::gpk::array_pod<char_t>					& output
	) {

	char										strFormat	[1024]			= {};
	char										filename	[1024]			= {};
	::gpk::array_obj<::bro::TCacheMissRecord>	cacheMisses;			
	do {
		gpk_necall(::bro::generate_output_for_db(databases, query, databaseName, output, cacheMisses), "%s", "Failed to load razor databases.");
		for(uint32_t iTableMiss = 0; iTableMiss < cacheMisses.size(); ++iTableMiss) {
			const ::bro::TCacheMissRecord				& tableMiss					= cacheMisses[iTableMiss];
			::gpk::view_const_string					tableName;
			int32_t										indexDB						= ::processThisTable(tableMiss.Key, databases, tableName);
			if(-1 == indexDB)
				continue;
			int64_t										iBlockLast					= -1LL;
			int64_t										iBlockCurrent				= 0;
			for(uint32_t iCacheMiss = 0; iCacheMiss < tableMiss.Val.size(); ++iCacheMiss) {
				const int64_t								absoluteRecordMiss			= tableMiss.Val[iCacheMiss];
				iBlockCurrent							= absoluteRecordMiss / databases[indexDB].Val.BlockSize;
				if(iBlockLast != iBlockCurrent) {
					iBlockLast								= iBlockCurrent;
					// Load db block
					databases.push_back({tableName, {}});
					const ::bro::TKeyValJSONDBV0					& refDB						= databases[indexDB];
					::bro::TKeyValJSONDBV0						& newDB						= databases[databases.size() - 1];
					newDB.Val.Bindings						= refDB.Val.Bindings	;
					newDB.Val.BlockSize						= refDB.Val.BlockSize	;
					newDB.Val.HostType						= refDB.Val.HostType	;
					newDB.Val.Range.Offset					= iBlockCurrent * newDB.Val.BlockSize;
					sprintf_s(strFormat, "%%.%us.%llu.json", newDB.Key.size(), iBlockCurrent);
					sprintf_s(filename, strFormat, newDB.Key.begin());
					::gpk::jsonFileRead(newDB.Val.Table, filename);
				}
				// Resolve expression
			}
		}
	} while(cacheMisses.size());
	return 0;
}


::gpk::error_t							razorprocessQueryV2
	( ::gpk::array_obj<::bro::TKeyValJSONDBV0>	& databases
	, const ::bro::SQuery						& query
	, const ::gpk::view_const_string			& databaseName
	, ::gpk::array_pod<char_t>					& output
	) {

	char										strFormat	[1024]			= {};
	char										filename	[1024]			= {};



	::gpk::array_obj<::bro::TCacheMissRecord>	cacheMisses;			
	do {
		gpk_necall(::bro::generate_output_for_db(databases, query, databaseName, output, cacheMisses), "%s", "Failed to load razor databases.");
		for(uint32_t iTableMiss = 0; iTableMiss < cacheMisses.size(); ++iTableMiss) {
			const ::bro::TCacheMissRecord				& tableMiss					= cacheMisses[iTableMiss];
			::gpk::view_const_string					tableName;
			int32_t										indexDB						= ::processThisTable(tableMiss.Key, databases, tableName);
			if(-1 == indexDB)
				continue;
			int64_t										iBlockLast					= -1LL;
			int64_t										iBlockCurrent				= 0;
			for(uint32_t iCacheMiss = 0; iCacheMiss < tableMiss.Val.size(); ++iCacheMiss) {
				const int64_t								absoluteRecordMiss			= tableMiss.Val[iCacheMiss];
				iBlockCurrent							= absoluteRecordMiss / databases[indexDB].Val.BlockSize;
				if(iBlockLast != iBlockCurrent) {
					iBlockLast								= iBlockCurrent;
					// Load db block
					databases.push_back({tableName, {}});
					const ::bro::TKeyValJSONDBV0					& refDB						= databases[indexDB];
					::bro::TKeyValJSONDBV0						& newDB						= databases[databases.size() - 1];
					newDB.Val.Bindings						= refDB.Val.Bindings	;
					newDB.Val.BlockSize						= refDB.Val.BlockSize	;
					newDB.Val.HostType						= refDB.Val.HostType	;
					newDB.Val.Range.Offset					= iBlockCurrent * newDB.Val.BlockSize;
					sprintf_s(strFormat, "%%.%us.%llu.json", newDB.Key.size(), iBlockCurrent);
					sprintf_s(filename, strFormat, newDB.Key.begin());
					::gpk::jsonFileRead(newDB.Val.Table, filename);
				}
				// Resolve expression
			}
		}
	} while(cacheMisses.size());
	return 0;
}
