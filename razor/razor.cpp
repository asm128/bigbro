#include "razor.h"

#include "gpk_stdstring.h"
#include "gpk_process.h"
#include "gpk_storage.h"

#include "gpk_json_expression.h"

::gpk::error_t									razor::loadDetail						(const ::gpk::view_array<::gpk::TKeyValConstString> & environViews, int32_t & detail)	{
	for(uint32_t iKey = 0; iKey < environViews.size(); ++iKey) {
		if(environViews[iKey].Key == ::gpk::view_const_string{"PATH_INFO"}) {
			uint64_t _detail = (uint64_t)-1LL;
			::gpk::stoull({&environViews[iKey].Val[1], environViews[iKey].Val.size() - 1}, &_detail);
			detail = (int32_t)_detail;
		}
	}
	return 0;
}

::gpk::error_t									razor::processQuery						
	( const ::gpk::view_array<const ::bro::TKeyValJSONDB>	& databases
	, const ::bro::SQuery									& query
	, const ::gpk::view_const_string						& databaseName
	, int32_t												detail
	, ::gpk::array_pod<char_t>								& output
	) {
	::gpk::array_obj<::bro::TCacheMissRecord>			cacheMisses;			
	do {
		gpk_necall(::bro::generate_output_for_db(databases, query, databaseName, detail, output, cacheMisses), "%s", "Failed to load razor databases.");	
	} while(cacheMisses.size());
	return 0;
}
