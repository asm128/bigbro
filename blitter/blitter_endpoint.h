#include "blitter.h"

#include "llc_cgi_app_impl_v2.h"
#include "llc_process.h"

#ifndef RAZOR_ENDPOINT_H_20190713
#define RAZOR_ENDPOINT_H_20190713

#define RAZOR_READONLY_ENDPOINT_IMPL(_endpointName, _configJsonFileName)																											\
LLC_CGI_JSON_APP_IMPL();																																							\
																																													\
::llc::error_t									llc_cgi_generate_output			(::llc::SCGIRuntimeValues & runtimeValues, ::llc::array_pod<char_t> & output)	{					\
	output.append(::llc::view_const_string{"Content-type: application/json\r\n"});																									\
	output.append(::llc::view_const_string{"\r\n"});																																\
	::razor::SRazorAppV0									app;																													\
	::llc::array_obj<::llc::TKeyValConstString>			environViews;																												\
	::llc::environmentBlockViews(runtimeValues.EntryPointArgs.EnvironmentBlock, environViews);																						\
	::llc::writeCGIEnvironToFile(environViews);																																		\
	/*if(0 == ::llc::keyValVerify(environViews, "REQUEST_METHOD", "GET")) {																											*/\
	/*	output.append(::llc::view_const_string{"{ \"status\" : 403, \"description\" :\"forbidden\" }\r\n"});																		*/\
	/*	return 1;																																									*/\
	/*}																																												*/\
	llc_necall(::razor::loadConfig(app, _configJsonFileName, runtimeValues.QueryStringKeyVals, environViews), "%s", "Failed to load detail.");										\
	llc_necall(::razor::processQuery(app.BigBro.Databases, app.BigBro.Query, _endpointName, output), "%s", "Failed to load razor databases.");										\
	if(output.size()) {																																								\
		OutputDebugStringA(output.begin());																																			\
		OutputDebugStringA("\n");																																					\
	}																																												\
	return 0;																																										\
}

#endif // RAZOR_ENDPOINT_H_20190713
