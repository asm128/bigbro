#include "blitter.h"

#include "llc_stdstring.h"
#include "llc_process.h"
#include "llc_storage.h"

#include "llc_json_expression.h"

static	::llc::error_t					loadDetail					(const ::llc::view_array<::llc::TKeyValConstString> & queryString, int64_t & detail)				{
	for(uint32_t iKey = 0; iKey < queryString.size(); ++iKey) {
		if(queryString[iKey].Key == ::llc::view_const_string{"PATH_INFO"}) {
			uint64_t									_detail						= (uint64_t)-1LL;
			::llc::stoull({&queryString[iKey].Val[1], queryString[iKey].Val.size() - 1}, &_detail);
			detail									= (int32_t)_detail;
		}
	}
	return 0;
}

::llc::error_t							razor::loadConfig			(::razor::SRazorAppV0 & appState, const ::llc::view_const_string & jsonFileName, const ::llc::view_array<::llc::TKeyValConstString> & queryString, const ::llc::view_array<::llc::TKeyValConstString> & environViews)	{
	llc_necall(::llc::jsonFileRead(appState.Config, jsonFileName), "Failed to load configuration file: %s.", jsonFileName.begin());
	llc_necall(::bro::configLoad(appState.BigBro, appState.Config.Reader), "%s", "Failed to load query.");
	llc_necall(::bro::queryLoad	(appState.BigBro.Query, queryString), "%s", "Failed to load query.");
	llc_necall(::loadDetail(environViews, appState.BigBro.Query.Detail), "%s", "Failed to load query.");
	return 0;
}

::llc::error_t							processThisTable			(const ::llc::view_const_string & missPath, const ::llc::view_array<const ::bro::TKeyValJSONDBV0>	& databases, ::llc::view_const_string & tableName)	{
	::llc::array_obj<::llc::view_const_string>	fieldsToExpand;
	::llc::split(missPath, '.', fieldsToExpand);
	const ::llc::view_const_string				fieldToExpand				= fieldsToExpand[fieldsToExpand.size() - 1];
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

::llc::error_t							razor::processQuery						
	( ::llc::array_obj<::bro::TKeyValJSONDBV0>	& databases
	, const ::bro::SQuery						& query
	, const ::llc::view_const_string			& databaseName
	, ::llc::array_pod<char_t>					& output
	) {

	char										strFormat	[1024]			= {};
	char										filename	[1024]			= {};
	::llc::array_obj<::bro::TCacheMissRecord>	cacheMisses;			
	do {
		llc_necall(::bro::generate_output_for_db(databases, query, databaseName, output, cacheMisses), "%s", "Failed to load razor databases.");
		for(uint32_t iTableMiss = 0; iTableMiss < cacheMisses.size(); ++iTableMiss) {
			const ::bro::TCacheMissRecord				& tableMiss					= cacheMisses[iTableMiss];
			::llc::view_const_string					tableName;
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
					::llc::jsonFileRead(newDB.Val.Table, filename);
				}
				// Resolve expression
			}
		}
	} while(cacheMisses.size());
	return 0;
}


::llc::error_t							razorprocessQueryV2
	( ::llc::array_obj<::bro::TKeyValJSONDBV0>	& databases
	, const ::bro::SQuery						& query
	, const ::llc::view_const_string			& databaseName
	, ::llc::array_pod<char_t>					& output
	) {

	char										strFormat	[1024]			= {};
	char										filename	[1024]			= {};



	::llc::array_obj<::bro::TCacheMissRecord>	cacheMisses;			
	do {
		llc_necall(::bro::generate_output_for_db(databases, query, databaseName, output, cacheMisses), "%s", "Failed to load razor databases.");
		for(uint32_t iTableMiss = 0; iTableMiss < cacheMisses.size(); ++iTableMiss) {
			const ::bro::TCacheMissRecord				& tableMiss					= cacheMisses[iTableMiss];
			::llc::view_const_string					tableName;
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
					sprintf_s(strFormat, "%%.%us.%llu.sson", newDB.Key.size(), iBlockCurrent);
					sprintf_s(filename, strFormat, newDB.Key.begin());
					::llc::jsonFileRead(newDB.Val.Table, filename);
				}
				// Resolve expression
			}
		}
	} while(cacheMisses.size());
	return 0;
}
