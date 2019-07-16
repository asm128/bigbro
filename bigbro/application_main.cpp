#include "application.h"

//#define GPK_AVOID_LOCAL_APPLICATION_MODULE_MODEL_EXECUTABLE_RUNTIME
#include "gpk_app_impl.h"

GPK_DEFINE_APPLICATION_ENTRY_POINT(::bba::SApplication, "Big Bro v0.1");

		::gpk::error_t										cleanup						(::bba::SApplication & app)						{
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

//#define BIGBRO_HEADLESS
::gpk::error_t												setupGUI					(::bba::SApplication & app)						{
	::gpk::SFramework												& framework					= app.Framework;
	::gpk::SDisplay													& mainWindow				= framework.MainDisplay;
	framework.Input.create();
	mainWindow.Size												= {320, 200};
	gerror_if(errored(::gpk::mainWindowCreate(mainWindow, framework.RuntimeValues.PlatformDetail, framework.Input)), "Failed to create main window why?????!?!?!?!?");
	::gpk::SGUI														& gui						= *framework.GUI;
	app.IdExit													= ::gpk::controlCreate(gui);
	::gpk::SControl													& controlExit				= gui.Controls.Controls[app.IdExit];
	controlExit.Area											= {{0, 0}, {64, 20}};
	controlExit.Border											= {1, 1, 1, 1};
	controlExit.Margin											= {1, 1, 1, 1};
	controlExit.Align											= ::gpk::ALIGN_BOTTOM_RIGHT;
	::gpk::SControlText												& controlText				= gui.Controls.Text[app.IdExit];
	controlText.Text											= "Exit";
	controlText.Align											= ::gpk::ALIGN_CENTER;
	::gpk::SControlConstraints										& controlConstraints		= gui.Controls.Constraints[app.IdExit];
	controlConstraints.AttachSizeToText.y						= app.IdExit;
	controlConstraints.AttachSizeToText.x						= app.IdExit;
	::gpk::controlSetParent(gui, app.IdExit, -1);

	::gpk::ptr_obj<::bba::TRenderTarget>							target;
	target->resize(app.Framework.MainDisplay.Size, {0xFF, 0x40, 0x7F, 0xFF}, (uint32_t)-1);
	::gpk::mutex_guard													lock					(app.LockGUI);
	::gpk::controlDrawHierarchy(*app.Framework.GUI, 0, target->Color.View);
	return 0;
}

		::gpk::error_t										setup						(::bba::SApplication & app)						{
	gpk_necall(::bba::loadConfig(app), "%s", "Failed to load application configuration.");
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
			::bba::TKeyValServerAsync										& serverKeyVal				= app.Servers[iServer];
			serverKeyVal.Key											= serverNames[iServer % 4];
			serverKeyVal.Val.create();
			::bba::SServerAsync												& serverCRUD				= *serverKeyVal.Val;
			gpk_necall(::gpk::serverStart(serverCRUD.UDPServer, (uint16_t)port, (int16_t)app.Adapter), "Failed to start server on port %u. Port busy?", (uint32_t)port);
			::gpk::sleep(100);
			++port;
		}
	}
	return 0;
}


#ifndef BIGBRO_HEADLESS
static	::gpk::error_t										updateDisplay				(::bba::SApplication & app)	{
	{
		::gpk::mutex_guard												lock						(app.LockRender);
		app.Framework.MainDisplayOffscreen							= app.Offscreen;
	}
	::gpk::SFramework												& framework					= app.Framework;
	retval_ginfo_if(::gpk::APPLICATION_STATE_EXIT, ::gpk::APPLICATION_STATE_EXIT == ::gpk::updateFramework(app.Framework), "Exit requested by framework update.");
	::gpk::SGUI														& gui						= *framework.GUI;
	::gpk::array_pod<uint32_t>										controlsToProcess			= {};
	::gpk::guiGetProcessableControls(gui, controlsToProcess);
	for(uint32_t iControl = 0, countControls = controlsToProcess.size(); iControl < countControls; ++iControl) {
		uint32_t														idControl					= controlsToProcess[iControl];
		const ::gpk::SControlState										& controlState				= gui.Controls.States[idControl];
		if(controlState.Execute) {
			info_printf("Executed %u.", idControl);
			if(idControl == (uint32_t)app.IdExit)
				return ::gpk::APPLICATION_STATE_EXIT;
		}
	}
	return 0;
}
#endif

		::gpk::error_t										update						(::bba::SApplication & app, bool exitSignal)	{
	::gpk::STimer													timer;
	retval_ginfo_if(::gpk::APPLICATION_STATE_EXIT, exitSignal, "Exit requested by runtime.");
#ifndef BIGBRO_HEADLESS
	retval_ginfo_if(::gpk::APPLICATION_STATE_EXIT, updateDisplay(app), "Exit requested by runtime.");
#endif
	gwarn_if(::bba::updateCRUDServer(app.BigBro, app.ServerAsync), "Failed to update server!");
	for(uint32_t iServer = 0; iServer < app.Servers.size(); ++iServer) {	// Update CRUD servers
		gwarn_if(::bba::updateCRUDServer(app.BigBro, *app.Servers[iServer].Val), "Failed to update server at index %i.", iServer);
		::gpk::sleep(1);
	}
	char															buffer[256]					= {};
	uint32_t														maxCount					= ::gpk::size(buffer);
	::gpk_moduleTitle(buffer, &maxCount);
	SetWindowTextA(app.Framework.MainDisplay.PlatformDetail.WindowHandle, buffer);
	timer.Frame();
	//warning_printf("Update time: %f.", (float)timer.LastTimeSeconds);
	return 0;
}

		::gpk::error_t										draw					(::bba::SApplication & app)						{
#if defined BIGBRO_HEADLESS
	(void)app;
#else
	::gpk::STimer													timer;
	::gpk::ptr_obj<::bba::TRenderTarget>							target;
	target.create();
	target->resize(app.Framework.MainDisplay.Size, {0xFF, 0x40, 0x7F, 0xFF}, (uint32_t)-1);
	{
		::gpk::mutex_guard												lock					(app.LockGUI);
		::gpk::controlDrawHierarchy(*app.Framework.GUI, 0, target->Color.View);
	}
	{
		::gpk::mutex_guard												lock					(app.LockRender);
		app.Offscreen												= target;
	}
	timer.Frame();
	//warning_printf("Draw time: %f.", (float)timer.LastTimeSeconds);
	::gpk::sleep(15);
#endif
	return 0;
}
