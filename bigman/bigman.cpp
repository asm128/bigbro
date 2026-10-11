#include "bigman.h"
#include "llc_json_expression.h"
#include "llc_parse.h"

::llc::error_t								bro::bigEyeLoadConfig			(::bro::SBigMan & app, const ::llc::view_const_string & fileNameJSONConfig)			{
	llc_necall(::llc::jsonFileRead(app.Config, fileNameJSONConfig), "Failed to load configuration file: '%s'.", fileNameJSONConfig.begin());

	{	// -- load ip from config file
		app.Client.AddressConnect					= {};
		::llc::tcpipAddress(9998, 0, ::llc::TRANSPORT_PROTOCOL_UDP, app.Client.AddressConnect);	// If loading the remote IP from the json fails, we fall back to the local address.
		::llc::view_const_string						jsonIP							= {};
		gwarn_if(errored(::llc::jsonExpressionResolve("remote_ip", app.Config.Reader, 0, jsonIP)), "Failed to load IP from json! Last contents found: %s.", jsonIP.begin())
		else {
			info_printf("Remote IP: %15.15s.", jsonIP.begin());
			gerror_if(errored(::llc::tcpipAddress(jsonIP, {}, app.Client.AddressConnect)), "Failed to read IP address from JSON config file: %s.", jsonIP.begin());	// turn the string into a SIPv4 struct.
		}
		// -- load port from config file
		app.Client.AddressConnect.Port					= 9998;
		jsonIP											= {};
		gwarn_if(errored(::llc::jsonExpressionResolve("remote_port"	, app.Config.Reader, 0, jsonIP)), "Failed to load port from json! Last contents found: %s.", jsonIP.begin()) 
		else {
			uint64_t											port							= 0;
			::llc::parseIntegerDecimal(jsonIP, &port);
			app.Client.AddressConnect.Port										= (uint16_t)port;
			info_printf("Remote port: %u.", (uint32_t)port);
		}
	}
	return 0;
}

