#include "application.h"
#include "gpk_bitmap_file.h"
#include "gpk_tcpip.h"
#include "gpk_find.h"
#include "gpk_process.h"

#include "gpk_parse.h"

//#define GPK_AVOID_LOCAL_APPLICATION_MODULE_MODEL_EXECUTABLE_RUNTIME
#include "gpk_app_impl.h"

GPK_DEFINE_APPLICATION_ENTRY_POINT(::bro::SApplication, "Module Explorer");

			::gpk::error_t											cleanup						(::bro::SApplication & app)						{
	::gpk::serverStop(app.ServerAsync.UDPServer);
	for(uint32_t iServer = 0; iServer < app.Servers.size(); ++iServer)
		::gpk::serverStop(app.Servers[iServer].Val->UDPServer);

	::gpk::mainWindowDestroy(app.Framework.MainDisplay);
	::gpk::tcpipShutdown();
	::gpk::sleep(1000);
	return 0;
}

static		::gpk::error_t											setupGUI					(::bro::SApplication & app)						{
	::gpk::SFramework														& framework					= app.Framework;
	::gpk::SDisplay															& mainWindow				= framework.MainDisplay;
	framework.Input.create();
	mainWindow.Size														= {320, 200};
	gerror_if(errored(::gpk::mainWindowCreate(mainWindow, framework.RuntimeValues.PlatformDetail, framework.Input)), "Failed to create main window why?????!?!?!?!?");
	::gpk::SGUI																& gui						= *framework.GUI;
	app.IdExit															= ::gpk::controlCreate(gui);
	::gpk::SControl															& controlExit				= gui.Controls.Controls[app.IdExit];
	controlExit.Area													= {{0, 0}, {64, 20}};
	controlExit.Border													= {1, 1, 1, 1};
	controlExit.Margin													= {1, 1, 1, 1};
	controlExit.Align													= ::gpk::ALIGN_BOTTOM_RIGHT;
	::gpk::SControlText														& controlText				= gui.Controls.Text[app.IdExit];
	controlText.Text													= "Exit";
	controlText.Align													= ::gpk::ALIGN_CENTER;
	::gpk::SControlConstraints												& controlConstraints		= gui.Controls.Constraints[app.IdExit];
	controlConstraints.AttachSizeToText.y								= app.IdExit;
	controlConstraints.AttachSizeToText.x								= app.IdExit;
	::gpk::controlSetParent(gui, app.IdExit, -1);
	return 0;
}

static		::gpk::error_t											loadConfig					(::bro::SApplication & app)						{
	::gpk::SFramework														& framework					= app.Framework;
	uint64_t																port						= 9998;
	uint64_t																adapter						= 0;
	{ // load port from config file
		::gpk::view_const_string												jsonPort					= {};
		const ::gpk::SJSONReader												& jsonReader				= framework.JSONConfig.Reader;
		const int32_t															indexObjectApp				= ::gpk::jsonExpressionResolve("application.bigbro", jsonReader, 0, jsonPort);
		gwarn_if(errored(indexObjectApp), "Failed to find application node (%s) in json configuration file: '%s'", "application.bigbro", framework.FileNameJSONConfig.begin())
		else {
			jsonPort															= "";
			gwarn_if(errored(::gpk::jsonExpressionResolve("listen_port"						, jsonReader, indexObjectApp, jsonPort)), "Failed to load config from json! Last contents found: %s.", jsonPort.begin()) 
			else {
				::gpk::parseIntegerDecimal(jsonPort, &port);
				info_printf("Port to listen on: %u.", (uint32_t)port);
			}
			jsonPort															= "";
			gwarn_if(errored(::gpk::jsonExpressionResolve("adapter"	, jsonReader, indexObjectApp, jsonPort)), "Failed to load config from json! Last contents found: %s.", jsonPort.begin()) 
			else {
				::gpk::parseIntegerDecimal(jsonPort, &adapter);
				info_printf("Adapter: %u.", (uint32_t)adapter);
			}
		}
	}
	app.BasePort														= (uint16_t)port;
	app.Adapter															= (uint16_t)adapter;
	return 0;
}
			::gpk::error_t											setup						(::bro::SApplication & app)						{
	gpk_necall(::loadConfig(app), "%s", "Failed to load application configuration.");
	gpk_necall(::setupGUI(app), "%s", "Failed to set up application graphical interface.");
	::gpk::tcpipInitialize();
	// Put every server to listen.
	uint16_t																port						= (uint16_t)app.BasePort;
	gpk_necall(::gpk::serverStart(app.ServerAsync.UDPServer, port, (int16_t)app.Adapter), "Failed to start server on port %u. Port busy?", (uint32_t)port);
	{ // Create CRUD servers.
		app.Servers.resize(8);
		const ::gpk::label														serverNames		[]			= 
			{ "Create"
			, "Read"
			, "Update"
			, "Delete"
			};
		for(uint32_t iServer = 0; iServer < app.Servers.size(); ++iServer) {
			++port;
			::bro::TKeyValServerAsync												& serverKeyVal				= app.Servers[iServer];
			serverKeyVal.Key													= serverNames[iServer % 4];
			serverKeyVal.Val.create();
			::bro::SServerAsync														& serverCRUD				= *serverKeyVal.Val;
			gpk_necall(::gpk::serverStart(serverCRUD.UDPServer, (uint16_t)port, (int16_t)app.Adapter), "Failed to start server on port %u. Port busy?", (uint32_t)port);
		}
	}
	return 0;
}

static	::gpk::error_t											updateDisplay						(::bro::SApplication & app)	{
	{
		::gpk::mutex_guard														lock						(app.LockRender);
		app.Framework.MainDisplayOffscreen									= app.Offscreen;
	}
	::gpk::SFramework														& framework					= app.Framework;
	retval_ginfo_if(::gpk::APPLICATION_STATE_EXIT, ::gpk::APPLICATION_STATE_EXIT == ::gpk::updateFramework(app.Framework), "Exit requested by framework update.");
	::gpk::SGUI																& gui						= *framework.GUI;
	::gpk::array_pod<uint32_t>												controlsToProcess			= {};
	::gpk::guiGetProcessableControls(gui, controlsToProcess);
	for(uint32_t iControl = 0, countControls = controlsToProcess.size(); iControl < countControls; ++iControl) {
		uint32_t																idControl					= controlsToProcess[iControl];
		const ::gpk::SControlState												& controlState				= gui.Controls.States[idControl];
		if(controlState.Execute) {
			info_printf("Executed %u.", idControl);
			if(idControl == (uint32_t)app.IdExit)
				return ::gpk::APPLICATION_STATE_EXIT;
		}
	}
	return 0;
}

		::gpk::error_t											updateCRUDServer			(::bro::SServerAsync & serverAsync)						{
	::gpk::array_obj<::gpk::array_obj<::gpk::ptr_obj<::gpk::SUDPConnectionMessage>>>	& receivedPerClient		= serverAsync.ReceivedPerClient;
	{	// pick up messages for later processing
		::gpk::mutex_guard																	lock						(serverAsync.UDPServer.Mutex);
		receivedPerClient.resize(serverAsync.UDPServer.Clients.size());
		for(uint32_t iClient = 0; iClient < serverAsync.UDPServer.Clients.size(); ++iClient) {
			::gpk::ptr_obj<::gpk::SUDPConnection>												conn						= serverAsync.UDPServer.Clients[iClient];
			::gpk::mutex_guard																	lockRecv					(conn->Queue.MutexReceive);
			receivedPerClient[iClient]														= serverAsync.UDPServer.Clients[iClient]->Queue.Received;
			serverAsync.UDPServer.Clients[iClient]->Queue.Received.clear();
		}
	}

	{	// Exectue processes
		for(uint32_t iClient = 0; iClient < receivedPerClient.size(); ++iClient) {
			for(uint32_t iMessage = 0; iMessage < receivedPerClient[iClient].size(); ++iMessage) {
				info_printf("Client %i received: %s.", iClient, receivedPerClient[iClient][iMessage]->Payload.begin());	
				::gpk::view_byte										environmentBlock		= receivedPerClient[iClient][iMessage]->Payload;
				// llamar proceso
				::gpk::view_const_byte									payload					= receivedPerClient[iClient][iMessage]->Payload;
				::gpk::error_t											contentOffset			= ::gpk::find_sequence_pod(::gpk::view_const_byte{"\0"}, payload);
				ce_if(errored(contentOffset), "Failed to find environment block stop code.");
				::gpk::view_const_char									contentBody				= {&payload[contentOffset + 2], payload.size() - contentOffset - 2};
				//if(payload.size() && (payload.size() > (uint32_t)contentOffset + 2))
				//	e_if(errored(::writeToPipe(app.ClientIOHandles[iClient], )), "Failed to write request content to process' stdin.");
			}
		}
	}
	Sleep(10);
	::gpk::array_obj<::gpk::array_obj<::gpk::array_pod<char_t>>>						& clientResponses		= serverAsync.ClientResponses;
	clientResponses.resize(receivedPerClient.size());
	{	// Read processes output if they're done processing.
		for(uint32_t iClient = 0; iClient < receivedPerClient.size(); ++iClient) {
			clientResponses[iClient].resize(receivedPerClient[iClient].size());
			for(uint32_t iMessage = 0; iMessage < receivedPerClient[iClient].size(); ++iMessage) {
				info_printf("Client %i received: %s.", iClient, receivedPerClient[iClient][iMessage]->Payload.begin());	
			// generar respuesta proceso
				clientResponses[iClient][iMessage]		= "";
				clientResponses[iClient][iMessage]		= "\r\n{ \"Respuesta\" : \"bleh\"}";
			//	::readFromPipe(process, iohandles, clientResponses[iClient][iMessage]);
			}
		}
	}
	for(uint32_t iClient = 0; iClient < clientResponses.size(); ++iClient) {
		for(uint32_t iMessage = 0; iMessage < clientResponses[iClient].size(); ++iMessage) { // contestar 
			if(clientResponses[iClient][iMessage].size()) {
				::gpk::mutex_guard														lock						(serverAsync.UDPServer.Mutex);
				::gpk::ptr_obj<::gpk::SUDPConnection>									conn						= serverAsync.UDPServer.Clients[iClient];
				::gpk::connectionPushData(*conn, conn->Queue, clientResponses[iClient][iMessage], true, true);
				receivedPerClient[iClient][iMessage]		= {};
			}
		}
	}
	return 0;
}

		::gpk::error_t											update						(::bro::SApplication & app, bool exitSignal)	{
	::gpk::STimer															timer;
	retval_ginfo_if(::gpk::APPLICATION_STATE_EXIT, exitSignal, "Exit requested by runtime.");
	retval_ginfo_if(::gpk::APPLICATION_STATE_EXIT, updateDisplay(app), "Exit requested by runtime.");

	updateCRUDServer(app.ServerAsync);
	for(uint32_t iServer = 0; iServer < app.Servers.size(); ++iServer)
		updateCRUDServer(*app.Servers[iServer].Val);

	//timer.Frame();
	//warning_printf("Update time: %f.", (float)timer.LastTimeSeconds);
	return 0;
}

			::gpk::error_t											draw					(::bro::SApplication & app)						{
	::gpk::STimer															timer;
	::gpk::ptr_obj<::gpk::SRenderTarget<::gpk::SColorBGRA, uint32_t>>		target;
	target.create();
	target->resize(app.Framework.MainDisplay.Size, {0xFF, 0x40, 0x7F, 0xFF}, (uint32_t)-1);
	{
		::gpk::mutex_guard														lock					(app.LockGUI);
		::gpk::controlDrawHierarchy(*app.Framework.GUI, 0, target->Color.View);
	}
	{
		::gpk::mutex_guard														lock					(app.LockRender);
		app.Offscreen														= target;
	}
	//timer.Frame();
	//warning_printf("Draw time: %f.", (float)timer.LastTimeSeconds);
	::gpk::sleep(15);
	return 0;
}
