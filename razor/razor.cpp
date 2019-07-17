#include "razor.h"

#include "gpk_stdstring.h"
#include "gpk_process.h"
#include "gpk_storage.h"

#include "gpk_json_expression.h"

static	::gpk::error_t							loadDetail									(const ::gpk::view_array<::gpk::TKeyValConstString> & queryString, int64_t & detail)				{
	for(uint32_t iKey = 0; iKey < queryString.size(); ++iKey) {
		if(queryString[iKey].Key == ::gpk::view_const_string{"PATH_INFO"}) {
			uint64_t _detail = (uint64_t)-1LL;
			::gpk::stoull({&queryString[iKey].Val[1], queryString[iKey].Val.size() - 1}, &_detail);
			detail = (int32_t)_detail;
		}
	}
	return 0;
}

::gpk::error_t									razor::loadConfig							(::razor::SRazorApp & appState, const ::gpk::view_array<::gpk::TKeyValConstString> & queryString)	{
	gpk_necall(::gpk::jsonFileRead(appState.Config, "razor.json"), "Failed to load configuration file: %s.", "razor.json");
	gpk_necall(::bro::loadConfig(appState.BigBro, appState.Config.Reader), "%s", "Failed to load query.");
	gpk_necall(::bro::loadQuery(appState.BigBro.Query, queryString), "%s", "Failed to load query.");
	gpk_necall(::loadDetail(queryString, appState.BigBro.Query.Detail), "%s", "Failed to load query.");
	return 0;
}


::gpk::error_t									razor::processQuery						
	( const ::gpk::view_array<const ::bro::TKeyValJSONDB>	& databases
	, const ::bro::SQuery									& query
	, const ::gpk::view_const_string						& databaseName
	, ::gpk::array_pod<char_t>								& output
	) {
	::gpk::array_obj<::bro::TCacheMissRecord>			cacheMisses;			
	do {
		gpk_necall(::bro::generate_output_for_db(databases, query, databaseName, output, cacheMisses), "%s", "Failed to load razor databases.");	
	} while(cacheMisses.size());
	return 0;
}
