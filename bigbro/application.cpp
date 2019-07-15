#include "application.h"

#include "bro_packet.h"

#include "gpk_bitmap_file.h"
#include "gpk_tcpip.h"
#include "gpk_find.h"
#include "gpk_process.h"

#include "gpk_parse.h"
#include "gpk_cgi.h"

//#define GPK_AVOID_LOCAL_APPLICATION_MODULE_MODEL_EXECUTABLE_RUNTIME
#include "gpk_app_impl.h"

GPK_DEFINE_APPLICATION_ENTRY_POINT(::bro::SApplication, "Big Bro v0.1");

		::gpk::error_t										cleanup						(::bro::SApplication & app)						{
	::gpk::serverStop(app.ServerAsync.UDPServer);
	for(uint32_t iServer = 0; iServer < app.Servers.size(); ++iServer)
		::gpk::serverStop(app.Servers[iServer].Val->UDPServer);

	::gpk::mainWindowDestroy(app.Framework.MainDisplay);
	::gpk::tcpipShutdown();
	::gpk::sleep(1000);
	return 0;
}

static	::gpk::error_t										loadServerConfig			(::bro::SApplication & app)						{
	::gpk::SFramework												& framework					= app.Framework;
	uint64_t														port						= 9998;
	uint64_t														adapter						= 0;
	{ // load port from config file
		::gpk::view_const_string										jsonResult					= {};
		const ::gpk::SJSONReader										& jsonReader				= framework.JSONConfig.Reader;
		const int32_t													indexObjectApp				= ::gpk::jsonExpressionResolve("application.bigbro", jsonReader, 0, jsonResult);
		gwarn_if(errored(indexObjectApp), "Failed to find application node (%s) in json configuration file: '%s'", "application.bigbro", framework.FileNameJSONConfig.begin())
		else {
			jsonResult															= "";
			gwarn_if(errored(::gpk::jsonExpressionResolve("listen_port", jsonReader, indexObjectApp, jsonResult)), "Failed to load config from json! Last contents found: %s.", jsonResult.begin()) 
			else {
				::gpk::parseIntegerDecimal(jsonResult, &port);
				info_printf("Port to listen on: %u.", (uint32_t)port);
			}
			jsonResult															= "";
			gwarn_if(errored(::gpk::jsonExpressionResolve("adapter"	, jsonReader, indexObjectApp, jsonResult)), "Failed to load config from json! Last contents found: %s.", jsonResult.begin()) 
			else {
				::gpk::parseIntegerDecimal(jsonResult, &adapter);
				info_printf("Adapter: %u.", (uint32_t)adapter);
			}
		}
	}
	app.BasePort														= (uint16_t)port;
	app.Adapter															= (uint16_t)adapter;
	return 0;
}

static	::gpk::error_t										loadConfig					(::bro::SApplication & app)						{
	gpk_necall(::loadServerConfig(app), "%s", "Error loading networking configuration.");
	gpk_necall(::bro::loadConfig(app.BigBro, app.Framework.JSONConfig.Reader), "%s", "Failed to load BigBro configuration.");
	return 0;
}

		::gpk::error_t										setupGUI					(::bro::SApplication & app);	// application_gui.cpp
		::gpk::error_t										setup						(::bro::SApplication & app)						{
	gpk_necall(::loadConfig(app), "%s", "Failed to load application configuration.");
	gpk_necall(::setupGUI(app), "%s", "Failed to set up application graphical interface.");
	::gpk::tcpipInitialize();
	// Put every server to listen.
	uint16_t														port						= (uint16_t)app.BasePort;
	gpk_necall(::gpk::serverStart(app.ServerAsync.UDPServer, port, (int16_t)app.Adapter), "Failed to start server on port %u. Port busy?", (uint32_t)port);
	{ // Create CRUD servers.
		app.Servers.resize(8);
		const ::gpk::label												serverNames		[]			= 
			{ "Create"
			, "Read"
			, "Update"
			, "Delete"
			};
		for(uint32_t iServer = 0; iServer < app.Servers.size(); ++iServer) {
			++port;
			::bro::TKeyValServerAsync										& serverKeyVal				= app.Servers[iServer];
			serverKeyVal.Key											= serverNames[iServer % 4];
			serverKeyVal.Val.create();
			::bro::SServerAsync												& serverCRUD				= *serverKeyVal.Val;
			gpk_necall(::gpk::serverStart(serverCRUD.UDPServer, (uint16_t)port, (int16_t)app.Adapter), "Failed to start server on port %u. Port busy?", (uint32_t)port);
			::gpk::sleep(100);
		}
	}
	return 0;
}

static	::gpk::error_t										updateDisplay						(::bro::SApplication & app)	{
	{
		::gpk::mutex_guard												lock						(app.LockRender);
		app.Framework.MainDisplayOffscreen							= app.Offscreen;
	}
	::gpk::SFramework												& framework					= app.Framework;
	retval_ginfo_if(::gpk::APPLICATION_STATE_EXIT, ::gpk::APPLICATION_STATE_EXIT == ::gpk::updateFramework(app.Framework), "Exit requested by framework update.");
	::gpk::SGUI															& gui						= *framework.GUI;
	::gpk::array_pod<uint32_t>											controlsToProcess			= {};
	::gpk::guiGetProcessableControls(gui, controlsToProcess);
	for(uint32_t iControl = 0, countControls = controlsToProcess.size(); iControl < countControls; ++iControl) {
		uint32_t															idControl					= controlsToProcess[iControl];
		const ::gpk::SControlState											& controlState				= gui.Controls.States[idControl];
		if(controlState.Execute) {
			info_printf("Executed %u.", idControl);
			if(idControl == (uint32_t)app.IdExit)
				return ::gpk::APPLICATION_STATE_EXIT;
		}
	}
	return 0;
}

static	::gpk::error_t										updateCRUDServer			(::bro::SBigBro & appState, ::bro::SServerAsync & serverAsync)						{
	::gpk::array_obj<::bro::TUDPReceiveQueue>						& receivedPerClient			= serverAsync.ReceivedPerClient;
	{	// Pick up messages for later processing in order to clear receive queues to avoid the connection's extra work.
		::gpk::mutex_guard																	lock						(serverAsync.UDPServer.Mutex);
		receivedPerClient.resize(serverAsync.UDPServer.Clients.size());
		for(uint32_t iClient = 0; iClient < serverAsync.UDPServer.Clients.size(); ++iClient) {
			::gpk::ptr_obj<::gpk::SUDPConnection>												conn						= serverAsync.UDPServer.Clients[iClient];
			::gpk::mutex_guard																	lockRecv					(conn->Queue.MutexReceive);
			receivedPerClient[iClient]														= serverAsync.UDPServer.Clients[iClient]->Queue.Received;
			serverAsync.UDPServer.Clients[iClient]->Queue.Received.clear();
		}
	}

	::gpk::array_obj<::bro::TUDPResponseQueue>								& clientResponses		= serverAsync.ClientResponses;
	clientResponses.resize(receivedPerClient.size());
	for(uint32_t iClient = 0; iClient < receivedPerClient.size(); ++iClient) {	// Process received packets.
		clientResponses[iClient].resize(receivedPerClient[iClient].size());
		for(uint32_t iMessage = 0; iMessage < receivedPerClient[iClient].size(); ++iMessage) {
			info_printf("Client %i received: %s.", iClient, receivedPerClient[iClient][iMessage]->Payload.begin());	
			::gpk::view_const_byte									payload					= receivedPerClient[iClient][iMessage]->Payload;
			::bro::SRequestPacket									packetReceived;
			::bro::requestRead(packetReceived, payload);
			::gpk::array_pod<byte_t>								& bytesResponse			= clientResponses[iClient][iMessage];
			bytesResponse										= ::gpk::view_const_string{"\r\n"};
			// Generate response
			{
				::bro::SQuery											& query						= appState.Query;
				::gpk::array_obj<::gpk::TKeyValConstString>				qsKeyVals;
				::gpk::array_obj<::gpk::view_const_string>				queryStringElements			= {};
				::gpk::querystring_split({packetReceived.QueryString.begin(), packetReceived.QueryString.size()}, queryStringElements);
				qsKeyVals.resize(queryStringElements.size());
				for(uint32_t iKeyVal = 0; iKeyVal < qsKeyVals.size(); ++iKeyVal) {
					::gpk::TKeyValConstString								& keyValDst				= qsKeyVals[iKeyVal];
					::gpk::keyval_split(queryStringElements[iKeyVal], keyValDst);
				}
				::bro::loadQuery(query, qsKeyVals);
				::gpk::view_const_string								dbName						= (packetReceived.Path.size() > 1) ? ::gpk::view_const_string{&packetReceived.Path[1], packetReceived.Path.size() - 1} : ::gpk::view_const_string{};
				::bro::generate_output_for_db(appState, dbName, -1, bytesResponse);
			}
			if(2 == bytesResponse.size())
				bytesResponse.append(::gpk::view_const_string{"{}"});
		}
	}

	for(uint32_t iClient = 0; iClient < clientResponses.size(); ++iClient) {
		for(uint32_t iMessage = 0; iMessage < clientResponses[iClient].size(); ++iMessage) { // contestar 
			if(0 == clientResponses[iClient][iMessage].size()) 
				continue;
			::gpk::mutex_guard														lock						(serverAsync.UDPServer.Mutex);
			::gpk::ptr_obj<::gpk::SUDPConnection>									conn						= serverAsync.UDPServer.Clients[iClient];
			::gpk::connectionPushData(*conn, conn->Queue, clientResponses[iClient][iMessage], true, true);
			receivedPerClient[iClient][iMessage]							= {};
		}
	}
	return 0;
}

		::gpk::error_t										update						(::bro::SApplication & app, bool exitSignal)	{
	::gpk::STimer													timer;
	retval_ginfo_if(::gpk::APPLICATION_STATE_EXIT, exitSignal, "Exit requested by runtime.");
	retval_ginfo_if(::gpk::APPLICATION_STATE_EXIT, updateDisplay(app), "Exit requested by runtime.");

	updateCRUDServer(app.BigBro, app.ServerAsync);
	for(uint32_t iServer = 0; iServer < app.Servers.size(); ++iServer) {
		updateCRUDServer(app.BigBro, *app.Servers[iServer].Val);
		::gpk::sleep(1);
	}

	char		buffer[256]		= {};
	uint32_t	maxCount		= ::gpk::size(buffer);
	::gpk_moduleTitle(buffer, &maxCount);
	SetWindowTextA(app.Framework.MainDisplay.PlatformDetail.WindowHandle, buffer);

	timer.Frame();
	//warning_printf("Update time: %f.", (float)timer.LastTimeSeconds);
	return 0;
}

//#define BIGBRO_DISABLE_DISPLAY

		::gpk::error_t										draw					(::bro::SApplication & app)						{
#if defined BIGBRO_DISABLE_DISPLAY
	(void)app;
#else
	::gpk::STimer														timer;
	::gpk::ptr_obj<::bro::TRenderTarget>								target;
	target.create();
	target->resize(app.Framework.MainDisplay.Size, {0xFF, 0x40, 0x7F, 0xFF}, (uint32_t)-1);
	{
		::gpk::mutex_guard													lock					(app.LockGUI);
		::gpk::controlDrawHierarchy(*app.Framework.GUI, 0, target->Color.View);
	}
	{
		::gpk::mutex_guard													lock					(app.LockRender);
		app.Offscreen														= target;
	}
	timer.Frame();
	//warning_printf("Draw time: %f.", (float)timer.LastTimeSeconds);
	::gpk::sleep(15);
#endif
	return 0;
}
