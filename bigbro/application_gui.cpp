#include "application.h"

::gpk::error_t												setupGUI					(::bro::SApplication & app)						{
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

	::gpk::ptr_obj<::bro::TRenderTarget>							target;
	target->resize(app.Framework.MainDisplay.Size, {0xFF, 0x40, 0x7F, 0xFF}, (uint32_t)-1);
	::gpk::mutex_guard													lock					(app.LockGUI);
	::gpk::controlDrawHierarchy(*app.Framework.GUI, 0, target->Color.View);
	return 0;
}
