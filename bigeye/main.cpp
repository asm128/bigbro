#include "bigeye.h"

#include "gpk_cgi.h"
#include "gpk_cgi_module.h"
#include "gpk_string_helper.h"
#include "gpk_process.h"
#include "gpk_json_expression.h"
#include "gpk_parse.h"
#include "gpk_storage.h"

#include <string>		// for ::std::stoi()

static	int											cgiBootstrap			(const ::gpk::SCGIRuntimeValues & runtimeValues, ::bro::SBigEye & appState, ::gpk::array_pod<char> & output)					{
	::gpk::array_obj<::gpk::TKeyValConstString>				environViews;																												\
	::gpk::environmentBlockViews(runtimeValues.EntryPointArgs.EnvironmentBlock, environViews);																						\
	if(0 == ::gpk::keyValVerify(environViews, "REQUEST_METHOD", "GET")) {																											\
		output.append(::gpk::view_const_string{"{ \"status\" : 403, \"description\" : \"Invalid request method\" }\r\n"});																		\
		return 1;																																									\
	}																																												\

	::gpk::array_pod<char_t>								environmentBlock		= runtimeValues.EntryPointArgs.EnvironmentBlock;
	{	// Prepare CGI environment and request content packet to send to the service.
		ree_if(errored(::gpk::environmentBlockFromEnviron(environmentBlock)), "%s", "Failed");
		environmentBlock.append(runtimeValues.Content.Body.begin(), runtimeValues.Content.Body.size());
		environmentBlock.push_back(0);
	}
	{	// Connect the client to the service.
		::gpk::SUDPClient										& udpClient				= appState.Client;
		gpk_necall(::gpk::clientConnect(udpClient), "%s", "error");
		::gpk::array_pod<char_t>								responseRemote;
		{	// Send the request data to the connected service.
			ree_if(udpClient.State != ::gpk::UDP_CONNECTION_STATE_IDLE, "%s", "Failed to connect to server.");
			gpk_necall(::gpk::connectionPushData(udpClient, udpClient.Queue, environmentBlock, true, true), "%s", "error");	// Enqueue the packet
			while(udpClient.State != ::gpk::UDP_CONNECTION_STATE_DISCONNECTED) {	// Loop until we ge the response or the client disconnects
				gpk_necall(::gpk::clientUpdate(udpClient), "%s", "error");	
				::gpk::array_obj<::gpk::ptr_obj<::gpk::SUDPConnectionMessage>>	received;
				{	// pick up messages for later processing
					::gpk::mutex_guard										lockRecv				(udpClient.Queue.MutexReceive);
					received											= udpClient.Queue.Received;
					udpClient.Queue.Received.clear();
				}
				if(received.size()) {	// Response has been received. Break loop.
					responseRemote										= received[0]->Payload;
					break;
				}
			}
		}
		//info_printf("Remote CGI answer: %s.", responseRemote.begin());
		gpk_necall(::gpk::clientDisconnect(udpClient), "%s", "error");
		output									= responseRemote;
	}
	return 0;
}

static int											cgiMain				(int argc, char** argv, char**envv)	{
	(void)(envv);
	::bro::SBigEye											appState;
	::bro::bigEyeLoadConfig(appState, "bigeye.json");

	::gpk::SCGIRuntimeValues								runtimeValues;
	gpk_necall(::gpk::cgiRuntimeValuesLoad(runtimeValues, {(const char**)argv, (uint32_t)argc}), "%s", "Failed to load cgi runtime values.");
	{
		gpk_necall(::gpk::tcpipInitialize(), "%s", "Failed to initialize network subsystem.");
		::gpk::array_pod<char>									html;
		if errored(::cgiBootstrap(runtimeValues, appState, html)) {
			printf("%s\r\n", "Content-Type: text/html"
				"\r\nCache-Control: no-store"
				"\r\n\r\n"
				"<html><head><title>Internal server error</title></head><body>Failed to process request.</body></html>"
				"\r\n"
				"\r\n"
			);
		}
		else {
			printf("%s\r\n", "Content-Type: application/json"
				"\r\nCache-Control: no-store"
			);
			html.push_back('\0');
			printf("%s", html.begin());
	#ifdef GPK_WINDOWS
			OutputDebugStringA(html.begin());
	#endif
		}
		gpk_necall(::gpk::tcpipShutdown(), "Failed to shut down network subsystem. %s", "Why??!?");
	}
	return 0;
}

int													main				(int argc, char** argv, char**envv)	{ return ::cgiMain(argc, argv, envv); }

#ifdef GPK_WINDOWS
#include <Windows.h>
int WINAPI											WinMain				
	(	_In_		HINSTANCE	hInstance
	,	_In_opt_	HINSTANCE	hPrevInstance
	,	_In_		LPSTR		lpCmdLine
	,	_In_		int			nShowCmd
	) {
	(void)hInstance, (void)hPrevInstance, (void)lpCmdLine, (void)nShowCmd;
	return ::cgiMain(__argc, __argv, environ);
}
#endif
