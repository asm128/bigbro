#include "bigman.h"

#include "bro_packet.h"

#include "llc_cgi.h"
#include "llc_cgi_module.h"
#include "llc_string_helper.h"
#include "llc_process.h"
#include "llc_json_expression.h"
#include "llc_parse.h"
#include "llc_storage.h"

#include <string>		// for ::std::stoi()

static	int											cgiBootstrap			(const ::llc::SCGIRuntimeValues & runtimeValues, ::bro::SBigMan & appState, ::llc::array_pod<char> & output)					{
	::llc::array_obj<::llc::TKeyValConstString>				environViews;
	::llc::environmentBlockViews(runtimeValues.EntryPointArgs.EnvironmentBlock, environViews);
	::llc::view_const_string								method;
	::llc::find("REQUEST_METHOD", environViews, method);
	if(method != ::llc::view_const_string{"PATCH"} && method != ::llc::view_const_string{"POST"}) {
		output.append(::llc::view_const_string{"{ \"status\" : 403, \"description\" : \"Invalid request method\" }\r\n"});
		return 1;
	}

	::llc::array_pod<byte_t>								bytesToSend;
	::bro::SRequestPacket									packetToSend;
	{
		packetToSend.Method									= 0 == ::llc::keyValVerify(environViews, "REQUEST_METHOD", "PATCH") ? ::llc::HTTP_METHOD_POST : ::llc::HTTP_METHOD_PATCH;
		::llc::find("PATH_INFO"		, environViews, packetToSend.Path);
		::llc::find("QUERY_STRING"	, environViews, packetToSend.QueryString);
		packetToSend.ContentBody							= runtimeValues.Content.Body;
	}
	::bro::requestWrite(packetToSend, bytesToSend);

	{	// Connect the client to the service.
		::llc::SUDPClient										& udpClient				= appState.Client;
		llc_necall(::llc::clientConnect(udpClient), "%s", "error");
		::llc::array_pod<char_t>								responseRemote;
		{	// Send the request data to the connected service.
			ree_if(udpClient.State != ::llc::UDP_CONNECTION_STATE_IDLE, "%s", "Failed to connect to server.");
			llc_necall(::llc::connectionPushData(udpClient, udpClient.Queue, bytesToSend, true, true), "%s", "error");	// Enqueue the packet
			while(udpClient.State != ::llc::UDP_CONNECTION_STATE_DISCONNECTED) {	// Loop until we ge the response or the client disconnects
				llc_necall(::llc::clientUpdate(udpClient), "%s", "error");	
				::llc::array_obj<::llc::ptr_obj<::llc::SUDPConnectionMessage>>	received;
				{	// pick up messages for later processing
					::llc::mutex_guard										lockRecv				(udpClient.Queue.MutexReceive);
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
		llc_necall(::llc::clientDisconnect(udpClient), "%s", "error");
		output									= responseRemote;
	}
	return 0;
}

static int											cgiMain				(int argc, char** argv, char**envv)	{
	(void)(envv);
	::bro::SBigMan											appState;
	::bro::bigEyeLoadConfig(appState, "bigman.json");

	::llc::SCGIRuntimeValues								runtimeValues;
	llc_necall(::llc::cgiRuntimeValuesLoad(runtimeValues, {(const char**)argv, (uint32_t)argc}), "%s", "Failed to load cgi runtime values.");
	{
		llc_necall(::llc::tcpipInitialize(), "%s", "Failed to initialize network subsystem.");
		::llc::array_pod<char>									html;
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
	#ifdef LLC_WINDOWS
			OutputDebugStringA(html.begin());
	#endif
		}
		llc_necall(::llc::tcpipShutdown(), "Failed to shut down network subsystem. %s", "Why??!?");
	}
	return 0;
}

int													main				(int argc, char** argv, char**envv)	{ return ::cgiMain(argc, argv, envv); }

#ifdef LLC_WINDOWS
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
