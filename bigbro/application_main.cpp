#include "application.h"

//#define LLC_AVOID_LOCAL_APPLICATION_MODULE_MODEL_EXECUTABLE_RUNTIME
#include "llc_app_impl.h"

LLC_DEFINE_APPLICATION_ENTRY_POINT(::bba::SApplication, "Big Bro v0.1");

		::llc::error_t										cleanup						(::bba::SApplication & app)						{
	::llc::serverStop(app.ServerAsync.UDPServer);
	for(uint32_t iServer = 0; iServer < app.Servers.size(); ++iServer) {
		::llc::serverStop(app.Servers[iServer].Val->UDPServer);
		::llc::sleep(50);
	}
#ifndef BIGBRO_HEADLESS
	::llc::mainWindowDestroy(app.Framework.MainDisplay);
#endif
	::llc::sleep(200);
	::llc::tcpipShutdown();
	::llc::sleep(200);
	return 0;
}

//#define BIGBRO_HEADLESS
::llc::error_t												setupGUI					(::bba::SApplication & app)						{
	::llc::SFramework												& framework					= app.Framework;
	::llc::SDisplay													& mainWindow				= framework.MainDisplay;
	framework.Input.create();
	mainWindow.Size												= {320, 200};
	gerror_if(errored(::llc::mainWindowCreate(mainWindow, framework.RuntimeValues.PlatformDetail, framework.Input)), "Failed to create main window why?????!?!?!?!?");
	::llc::SGUI														& gui						= *framework.GUI;
	app.IdExit													= ::llc::controlCreate(gui);
	::llc::SControl													& controlExit				= gui.Controls.Controls[app.IdExit];
	controlExit.Area											= {{0, 0}, {64, 20}};
	controlExit.Border											= {1, 1, 1, 1};
	controlExit.Margin											= {1, 1, 1, 1};
	controlExit.Align											= ::llc::ALIGN_BOTTOM_RIGHT;
	::llc::SControlText												& controlText				= gui.Controls.Text[app.IdExit];
	controlText.Text											= "Exit";
	controlText.Align											= ::llc::ALIGN_CENTER;
	::llc::SControlConstraints										& controlConstraints		= gui.Controls.Constraints[app.IdExit];
	controlConstraints.AttachSizeToText.y						= app.IdExit;
	controlConstraints.AttachSizeToText.x						= app.IdExit;
	::llc::controlSetParent(gui, app.IdExit, -1);

	::llc::ptr_obj<::bba::TRenderTarget>							target;
	target->resize(app.Framework.MainDisplay.Size, {0xFF, 0x40, 0x7F, 0xFF}, (uint32_t)-1);
	::llc::mutex_guard													lock					(app.LockGUI);
	::llc::controlDrawHierarchy(*app.Framework.GUI, 0, target->Color.View);
	return 0;
}

		::llc::error_t										setup						(::bba::SApplication & app)						{
	llc_necall(::bba::loadConfig(app), "%s", "Failed to load application configuration.");
#ifndef BIGBRO_HEADLESS
	llc_necall(::setupGUI(app), "%s", "Failed to set up application graphical interface.");
#endif
	::llc::tcpipInitialize();
	// Put every server to listen.
	uint16_t														port						= (uint16_t)app.BasePort;
	llc_necall(::llc::serverStart(app.ServerAsync.UDPServer, port, (int16_t)app.Adapter), "Failed to start server on port %u. Port busy?", (uint32_t)port);
	++port;
	{ // Create CRUD servers.
		app.Servers.resize(8);	// TODO: Move server count to JSON config file.
		const ::llc::label												serverNames		[]			= 
			{ "Create"
			, "Read"
			, "Update"
			, "Delete"
			};
		for(uint32_t iServer = 0; iServer < app.Servers.size(); ++iServer) {
			::bba::TKeyValServerAsync										& serverKeyVal				= app.Servers[iServer];
			serverKeyVal.Key											= serverNames[iServer % 4];
			serverKeyVal.Val.create();
			::bba::SServerAsync												& serverCRUD				= *serverKeyVal.Val;
			llc_necall(::llc::serverStart(serverCRUD.UDPServer, (uint16_t)port, (int16_t)app.Adapter), "Failed to start server on port %u. Port busy?", (uint32_t)port);
			::llc::sleep(100);
			++port;
		}
	}
	return 0;
}


#ifndef BIGBRO_HEADLESS
static	::llc::error_t										updateDisplay				(::bba::SApplication & app)	{
	{
		::llc::mutex_guard												lock						(app.LockRender);
		app.Framework.MainDisplayOffscreen							= app.Offscreen;
	}
	::llc::SFramework												& framework					= app.Framework;
	retval_ginfo_if(::llc::APPLICATION_STATE_EXIT, ::llc::APPLICATION_STATE_EXIT == ::llc::updateFramework(app.Framework), "Exit requested by framework update.");
	::llc::SGUI														& gui						= *framework.GUI;
	::llc::array_pod<uint32_t>										controlsToProcess			= {};
	::llc::guiGetProcessableControls(gui, controlsToProcess);
	for(uint32_t iControl = 0, countControls = controlsToProcess.size(); iControl < countControls; ++iControl) {
		uint32_t														idControl					= controlsToProcess[iControl];
		const ::llc::SControlState										& controlState				= gui.Controls.States[idControl];
		if(controlState.Execute) {
			info_printf("Executed %u.", idControl);
			if(idControl == (uint32_t)app.IdExit)
				return ::llc::APPLICATION_STATE_EXIT;
		}
	}
	return 0;
}
#endif

		::llc::error_t										update						(::bba::SApplication & app, bool exitSignal)	{
	::llc::STimer													timer;
	retval_ginfo_if(::llc::APPLICATION_STATE_EXIT, exitSignal, "Exit requested by runtime.");
#ifndef BIGBRO_HEADLESS
	retval_ginfo_if(::llc::APPLICATION_STATE_EXIT, updateDisplay(app), "Exit requested by runtime.");
#endif
	gwarn_if(::bba::updateCRUDServer(app.BigBro, app.ServerAsync), "Failed to update server!");
	for(uint32_t iServer = 0; iServer < app.Servers.size(); ++iServer) {	// Update CRUD servers
		gwarn_if(::bba::updateCRUDServer(app.BigBro, *app.Servers[iServer].Val), "Failed to update server at index %i.", iServer);
		::llc::sleep(1);
	}
	char															buffer[256]					= {};
	uint32_t														maxCount					= ::llc::size(buffer);
	::llc_moduleTitle(buffer, &maxCount);
	SetWindowTextA(app.Framework.MainDisplay.PlatformDetail.WindowHandle, buffer);
	timer.Frame();
	//warning_printf("Update time: %f.", (float)timer.LastTimeSeconds);
	return 0;
}

		::llc::error_t										draw					(::bba::SApplication & app)						{
#if defined BIGBRO_HEADLESS
	(void)app;
#else
	::llc::STimer													timer;
	::llc::ptr_obj<::bba::TRenderTarget>							target;
	target.create();
	target->resize(app.Framework.MainDisplay.Size, {0xFF, 0x40, 0x7F, 0xFF}, (uint32_t)-1);
	{
		::llc::mutex_guard												lock					(app.LockGUI);
		::llc::controlDrawHierarchy(*app.Framework.GUI, 0, target->Color.View);
	}
	{
		::llc::mutex_guard												lock					(app.LockRender);
		app.Offscreen												= target;
	}
	timer.Frame();
	//warning_printf("Draw time: %f.", (float)timer.LastTimeSeconds);
	::llc::sleep(15);
#endif
	return 0;
}
