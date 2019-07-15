#include "bigman.h"
#include "gpk_json_expression.h"
#include "gpk_parse.h"

::gpk::error_t								bro::bigEyeLoadConfig			(::bro::SBigMan & app, const ::gpk::view_const_string & fileNameJSONConfig)			{
	gpk_necall(::gpk::jsonFileRead(app.Config, fileNameJSONConfig), "Failed to load configuration file: '%s'.", fileNameJSONConfig.begin());

	{	// -- load ip from config file
		app.Client.AddressConnect					= {};
		::gpk::tcpipAddress(9998, 0, ::gpk::TRANSPORT_PROTOCOL_UDP, app.Client.AddressConnect);	// If loading the remote IP from the json fails, we fall back to the local address.
		::gpk::view_const_string						jsonIP							= {};
		gwarn_if(errored(::gpk::jsonExpressionResolve("remote_ip", app.Config.Reader, 0, jsonIP)), "Failed to load IP from json! Last contents found: %s.", jsonIP.begin())
		else {
			info_printf("Remote IP: %15.15s.", jsonIP.begin());
			gerror_if(errored(::gpk::tcpipAddress(jsonIP, {}, app.Client.AddressConnect)), "Failed to read IP address from JSON config file: %s.", jsonIP.begin());	// turn the string into a SIPv4 struct.
		}
		// -- load port from config file
		app.Client.AddressConnect.Port					= 9998;
		jsonIP											= {};
		gwarn_if(errored(::gpk::jsonExpressionResolve("remote_port"	, app.Config.Reader, 0, jsonIP)), "Failed to load port from json! Last contents found: %s.", jsonIP.begin()) 
		else {
			uint64_t											port							= 0;
			::gpk::parseIntegerDecimal(jsonIP, &port);
			app.Client.AddressConnect.Port										= (uint16_t)port;
			info_printf("Remote port: %u.", (uint32_t)port);
		}
	}
	return 0;
}

