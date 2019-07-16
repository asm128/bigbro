#include "application.h"

#include "bro_packet.h"

#include "gpk_tcpip.h"
#include "gpk_find.h"
#include "gpk_process.h"

#include "gpk_parse.h"
#include "gpk_cgi.h"
#include "gpk_stdstring.h"

//#define GPK_AVOID_LOCAL_APPLICATION_MODULE_MODEL_EXECUTABLE_RUNTIME
#include "gpk_app_impl.h"

GPK_DEFINE_APPLICATION_ENTRY_POINT(::bro::SApplication, "Big Bro v0.1");

//#define BIGBRO_HEADLESS

		::gpk::error_t										cleanup						(::bro::SApplication & app)						{
	::gpk::serverStop(app.ServerAsync.UDPServer);
	for(uint32_t iServer = 0; iServer < app.Servers.size(); ++iServer) {
		::gpk::serverStop(app.Servers[iServer].Val->UDPServer);
		::gpk::sleep(50);
	}
#ifndef BIGBRO_HEADLESS
	::gpk::mainWindowDestroy(app.Framework.MainDisplay);
#endif
	::gpk::sleep(200);
	::gpk::tcpipShutdown();
	::gpk::sleep(200);
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
			jsonResult													= "";
			gwarn_if(errored(::gpk::jsonExpressionResolve("listen_port", jsonReader, indexObjectApp, jsonResult)), "Failed to load config from json! Last contents found: %s.", jsonResult.begin()) 
			else {
				::gpk::parseIntegerDecimal(jsonResult, &port);
				info_printf("Port to listen on: %u.", (uint32_t)port);
			}
			jsonResult													= "";
			gwarn_if(errored(::gpk::jsonExpressionResolve("adapter", jsonReader, indexObjectApp, jsonResult)), "Failed to load config from json! Last contents found: %s.", jsonResult.begin()) 
			else {
				::gpk::parseIntegerDecimal(jsonResult, &adapter);
				info_printf("Adapter: %u.", (uint32_t)adapter);
			}
		}
	}
	app.BasePort												= (uint16_t)port;
	app.Adapter													= (uint16_t)adapter;
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
#ifndef BIGBRO_HEADLESS
	gpk_necall(::setupGUI(app), "%s", "Failed to set up application graphical interface.");
#endif
	::gpk::tcpipInitialize();
	// Put every server to listen.
	uint16_t														port						= (uint16_t)app.BasePort;
	gpk_necall(::gpk::serverStart(app.ServerAsync.UDPServer, port, (int16_t)app.Adapter), "Failed to start server on port %u. Port busy?", (uint32_t)port);
	++port;
	{ // Create CRUD servers.
		app.Servers.resize(8);	// TODO: Move server count to JSON config file.
		const ::gpk::label												serverNames		[]			= 
			{ "Create"
			, "Read"
			, "Update"
			, "Delete"
			};
		for(uint32_t iServer = 0; iServer < app.Servers.size(); ++iServer) {
			::bro::TKeyValServerAsync										& serverKeyVal				= app.Servers[iServer];
			serverKeyVal.Key											= serverNames[iServer % 4];
			serverKeyVal.Val.create();
			::bro::SServerAsync												& serverCRUD				= *serverKeyVal.Val;
			gpk_necall(::gpk::serverStart(serverCRUD.UDPServer, (uint16_t)port, (int16_t)app.Adapter), "Failed to start server on port %u. Port busy?", (uint32_t)port);
			::gpk::sleep(100);
			++port;
		}
	}
	return 0;
}

static	::gpk::error_t										processPayload				(::bro::SBigBro & appState, const ::gpk::view_const_byte & payload, ::gpk::array_pod<char_t> & partialResult, ::gpk::array_pod<char_t> & bytesResponse)						{
	::bro::SRequestPacket											packetReceived;
	::bro::requestRead(packetReceived, payload);
	{	// --- Retrieve query from request.
		::gpk::array_obj<::gpk::TKeyValConstString>						qsKeyVals;
		::gpk::array_obj<::gpk::view_const_string>						queryStringElements			= {};
		::gpk::querystring_split({packetReceived.QueryString.begin(), packetReceived.QueryString.size()}, queryStringElements);
		qsKeyVals.resize(queryStringElements.size());
		for(uint32_t iKeyVal = 0; iKeyVal < qsKeyVals.size(); ++iKeyVal) {
			::gpk::TKeyValConstString										& keyValDst					= qsKeyVals[iKeyVal];
			::gpk::keyval_split(queryStringElements[iKeyVal], keyValDst);
		}
		::bro::loadQuery(appState.Query, qsKeyVals);
	}
	// --- Generate response
	::gpk::view_const_string										dbName						= (packetReceived.Path.size() > 1) ? ::gpk::view_const_string{&packetReceived.Path[1], packetReceived.Path.size() - 1} : ::gpk::view_const_string{};;
	uint64_t														detail						= (uint64_t)-1LL;
	{	// --- Retrieve detail part 
		::gpk::view_const_string										strDetail					= {};
		const ::gpk::error_t											indexOfLastBar				= ::gpk::rfind('/', dbName);
		const uint32_t													startOfDetail				= (uint32_t)(indexOfLastBar + 1);
		if(indexOfLastBar > 0 && startOfDetail < dbName.size()) {
			strDetail													= {&dbName[startOfDetail], dbName.size() - startOfDetail};
			dbName														= {dbName.begin(), (uint32_t)indexOfLastBar};
			if(strDetail.size())
				::gpk::stoull(strDetail, &detail);
		}
	}
	if(0 != dbName.size()) {
		::gpk::array_obj<::gpk::SKeyVal<::gpk::view_const_string, int64_t>>	cacheMisses;
		::bro::generate_output_for_db(appState.Databases, appState.Query, dbName, (uint32_t)detail, partialResult, cacheMisses);
		if(0 == cacheMisses.size()) {
			bytesResponse.append(partialResult);
			partialResult.clear();
		}
		else {
			char format[256];
			bytesResponse.clear();
			for(uint32_t iMiss = 0; iMiss < cacheMisses.size(); ++iMiss) {
				sprintf_s(format, "Cache Miss: %%.%us[%lli]", cacheMisses[iMiss].Key.size(), cacheMisses[iMiss].Val);
				info_printf(format, cacheMisses[iMiss].Key.begin());
			}
		}
	}
	return 0;
}

static	::gpk::error_t										updateCRUDServer			(::bro::SBigBro & appState, ::bro::SServerAsync & serverAsync)						{
	::gpk::array_obj<::bro::TUDPReceiveQueue>						& receivedPerClient			= serverAsync.ReceivedPerClient;
	{	// Pick up messages for later processing in order to clear receive queues to avoid the connection's extra work.
		::gpk::mutex_guard												lock						(serverAsync.UDPServer.Mutex);
		receivedPerClient.resize(serverAsync.UDPServer.Clients.size());
		for(uint32_t iClient = 0; iClient < serverAsync.UDPServer.Clients.size(); ++iClient) {
			::gpk::ptr_obj<::gpk::SUDPConnection>							conn						= serverAsync.UDPServer.Clients[iClient];
			::gpk::mutex_guard												lockRecv					(conn->Queue.MutexReceive);
			receivedPerClient[iClient]									= serverAsync.UDPServer.Clients[iClient]->Queue.Received;
			serverAsync.UDPServer.Clients[iClient]->Queue.Received.clear();
		}
	}

	::gpk::array_obj<::bro::TUDPResponseQueue>						& clientResponses			= serverAsync.ClientResponses;
	::gpk::array_obj<::bro::TUDPResponseQueue>						& partialResults			= serverAsync.PartialResults;
	clientResponses	.resize(receivedPerClient.size());	// we need one output queue for each input queue
	partialResults	.resize(receivedPerClient.size());	// we need one output queue for each input queue
	for(uint32_t iClient = 0; iClient < receivedPerClient.size(); ++iClient) {	// Process received packets.
		::bro::TUDPReceiveQueue											& clientReceived			= receivedPerClient[iClient];
		clientResponses	[iClient].resize(clientReceived.size());		// we need one output message for each received message
		partialResults	[iClient].resize(clientReceived.size());		// we need one output message for each received message
		for(uint32_t iMessage = 0; iMessage < clientReceived.size(); ++iMessage) {
			info_printf("Client %i received: %s.", iClient, clientReceived[iMessage]->Payload.begin());	
			::gpk::view_const_byte											payload						= clientReceived[iMessage]->Payload;
			::gpk::array_pod<byte_t>										& bytesResponse				= clientResponses[iClient][iMessage];
			::gpk::array_pod<byte_t>										& partialResult				= partialResults[iClient][iMessage];
			bytesResponse												= ::gpk::view_const_string{"\r\n"};
			::processPayload(appState, payload, partialResult, bytesResponse);
			if(2 == bytesResponse.size() && 0 == partialResult.size())
				bytesResponse.append(::gpk::view_const_string{"{}"});
		}
	}

	for(uint32_t iClient = 0; iClient < clientResponses.size(); ++iClient) {
		for(uint32_t iMessage = 0; iMessage < clientResponses[iClient].size(); ++iMessage) { // Send generated responses 
			const ::gpk::view_const_byte									message						= clientResponses[iClient][iMessage];
			if(0 == message.size()) 
				continue;
			::gpk::mutex_guard												lock						(serverAsync.UDPServer.Mutex);
			::gpk::ptr_obj<::gpk::SUDPConnection>							conn						= serverAsync.UDPServer.Clients[iClient];
			::gpk::connectionPushData(*conn, conn->Queue, message, true, true, 10);
			receivedPerClient[iClient][iMessage]						= {};	// Clear received message.
		}
	}
	return 0;
}

#ifndef BIGBRO_HEADLESS
static	::gpk::error_t										updateDisplay				(::bro::SApplication & app)	{
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
#endif

		::gpk::error_t										update						(::bro::SApplication & app, bool exitSignal)	{
	::gpk::STimer													timer;
	retval_ginfo_if(::gpk::APPLICATION_STATE_EXIT, exitSignal, "Exit requested by runtime.");
#ifndef BIGBRO_HEADLESS
	retval_ginfo_if(::gpk::APPLICATION_STATE_EXIT, updateDisplay(app), "Exit requested by runtime.");
#endif
	gwarn_if(::updateCRUDServer(app.BigBro, app.ServerAsync), "Failed to update server!");
	for(uint32_t iServer = 0; iServer < app.Servers.size(); ++iServer) {	// Update CRUD servers
		gwarn_if(::updateCRUDServer(app.BigBro, *app.Servers[iServer].Val), "Failed to update server at index %i.", iServer);
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

		::gpk::error_t										draw					(::bro::SApplication & app)						{
#if defined BIGBRO_HEADLESS
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
