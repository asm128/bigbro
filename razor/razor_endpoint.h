#include "razor.h"

#include "gpk_cgi_app_impl_v2.h"

#include "gpk_process.h"
#include "gpk_storage.h"

#ifndef RAZOR_ENDPOINT_H_20190713
#define RAZOR_ENDPOINT_H_20190713

#define RAZOR_READONLY_ENDPOINT_IMPL(_endpointName)																																	\
GPK_CGI_JSON_APP_IMPL();																																							\
																																													\
::gpk::error_t									gpk_cgi_generate_output			(::gpk::SCGIRuntimeValues & runtimeValues, ::gpk::array_pod<char_t> & output)					{	\
	output.append(::gpk::view_const_string{"\r\n"});																																\
	::razor::SRazorApp									app;																														\
	::gpk::array_obj<::gpk::TKeyValConstString>			environViews;																												\
	::gpk::environmentBlockViews(runtimeValues.EntryPointArgs.EnvironmentBlock, environViews);																						\
	::gpk::array_pod<char_t>							environmentBlock				= runtimeValues.EntryPointArgs.EnvironmentBlock; \
																																		 \
	for(uint32_t iChar = 0; iChar < environmentBlock.size(); ++iChar)																	 \
		if(0 == environmentBlock[iChar])																								 \
			environmentBlock[iChar] = '¿';																								 \
																																		 \
	for(uint32_t iKey = 0; iKey < environViews.size(); ++iKey)																			 \
		if(environViews[iKey].Key == ::gpk::view_const_string{"REMOTE_ADDR"}) {															 \
			::gpk::array_pod<char_t> temp;																								 \
			::gpk::fileToMemory(environViews[iKey].Val, temp);																			 \
			temp.append(environmentBlock);																								 \
			temp.push_back('\r');																										 \
			temp.push_back('\n');																										 \
			::gpk::fileFromMemory(environViews[iKey].Val, temp);																		 \
			break;																														 \
		}																																 \
																																		 \
																																		 \
	if(0 == ::gpk::keyValVerify(environViews, "REQUEST_METHOD", "GET")) {																											\
		output.append(::gpk::view_const_string{"{ \"status\" : 403, \"description\" :\"forbidden\" }\r\n"});																		\
		return 1;																																									\
	}																																												\
	::gpk::jsonFileRead(app.Config, "bigbro.json");																																	\
	gpk_necall(::bro::loadConfig(app.BigBro, app.Config.Reader), "%s", "Failed to load query.");																					\
	gpk_necall(::razor::loadCWD(environViews, app.CWD), "%s", "Failed to load query.");																								\
	gpk_necall(::bro::loadQuery(app.BigBro.Query, runtimeValues.QueryStringKeyVals), "%s", "Failed to load query.");																\
	int32_t												detail							= -1;																						\
	gpk_necall(::razor::loadDetail(environViews,detail), "%s", "Failed to load detail.");																							\
	::gpk::array_pod<int32_t>							cacheMisses;																												\
	gpk_necall(::bro::generate_output_for_db(app.BigBro, _endpointName, detail, output, cacheMisses), "%s", "Failed to load razor databases.");										\
	return 0;																																										\
}

#endif // RAZOR_ENDPOINT_H_20190713
