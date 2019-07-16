#include "application.h"

#include "bro_packet.h"

#include "gpk_tcpip.h"
#include "gpk_find.h"
#include "gpk_process.h"

#include "gpk_parse.h"
#include "gpk_cgi.h"
#include "gpk_stdstring.h"


static	::gpk::error_t										loadServerConfig			(::bba::SApplication & app)						{
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

::gpk::error_t												bba::loadConfig					(::bba::SApplication & app)						{
	gpk_necall(::loadServerConfig(app), "%s", "Error loading networking configuration.");
	gpk_necall(::bro::loadConfig(app.BigBro, app.Framework.JSONConfig.Reader), "%s", "Failed to load BigBro configuration.");
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
			::gpk::array_obj<::gpk::SKeyVal<::gpk::view_const_string, int64_t>>	cacheMissesFolded;
			for(uint32_t iMiss = 0; iMiss < cacheMisses.size(); ++iMiss) {
				bool														bFolded			= false;
				const ::gpk::SKeyVal<::gpk::view_const_string, int64_t>		& miss			= cacheMisses[iMiss];
				for(uint32_t iFolded = 0; iFolded < cacheMissesFolded.size(); ++iFolded) { 
					const ::gpk::SKeyVal<::gpk::view_const_string, int64_t>	& missFolded	= cacheMissesFolded[iFolded];
					if(miss.Key == missFolded.Key && miss.Val == missFolded.Val) {
						bFolded					= true;
						break;
					}
				}
				if(bFolded)
					continue;
				cacheMissesFolded.push_back(miss);
			}
			for(uint32_t iMiss = 0; iMiss < cacheMissesFolded.size(); ++iMiss) {
				const ::gpk::SKeyVal<::gpk::view_const_string, int64_t>	& missFolded	= cacheMissesFolded[iMiss];
				sprintf_s(format, "Cache Miss: %%.%us[%lli]", missFolded.Key.size(), missFolded.Val);
				info_printf(format, missFolded.Key.begin());
			}
		}
	}
	return 0;
}

// Pick up messages for later processing in order to clear receive queues to avoid the connection's extra work.
static	::gpk::error_t										pickUpQueueReceived			(::bba::SServerAsync & serverAsync)						{
	::gpk::array_obj<::bba::TUDPReceiveQueue>						& receivedPerClient			= serverAsync.ReceivedPerClient;
	::gpk::array_obj<::gpk::array_pod<::bba::CONNECTION_STATE>>		& requestStates				= serverAsync.RequestStates;
	{
		::gpk::mutex_guard												lock						(serverAsync.UDPServer.Mutex);
		receivedPerClient	.resize(serverAsync.UDPServer.Clients.size());
		requestStates		.resize(serverAsync.UDPServer.Clients.size(), ::bba::CONNECTION_STATE_IDLE);
		for(uint32_t iClient = 0; iClient < serverAsync.UDPServer.Clients.size(); ++iClient) {
			::gpk::ptr_obj<::gpk::SUDPConnection>							conn						= serverAsync.UDPServer.Clients[iClient];
			::gpk::mutex_guard												lockRecv					(conn->Queue.MutexReceive);
			receivedPerClient[iClient]									= conn->Queue.Received;
			conn->Queue.Received.clear();
		}
	}
	return 0;
}

// Send generated responses 
static	::gpk::error_t										sendGeneratedResponses		(::bba::SServerAsync & serverAsync)						{
	::gpk::array_obj<::bba::TUDPResponseQueue>						& clientResponses			= serverAsync.ClientResponses;
	::gpk::array_obj<::bba::TUDPReceiveQueue>						& receivedPerClient			= serverAsync.ReceivedPerClient;
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

::gpk::error_t												bba::updateCRUDServer		(::bro::SBigBro & appState, ::bba::SServerAsync & serverAsync)						{
	::pickUpQueueReceived(serverAsync);

	::gpk::array_obj<::bba::TUDPReceiveQueue>						& receivedPerClient			= serverAsync.ReceivedPerClient;
	::gpk::array_obj<::bba::TUDPResponseQueue>						& clientResponses			= serverAsync.ClientResponses;
	::gpk::array_obj<::bba::TUDPResponseQueue>						& partialResults			= serverAsync.PartialResults;
	clientResponses		.resize(receivedPerClient.size());	// we need one output queue for each input queue
	partialResults		.resize(receivedPerClient.size());	// we need one output queue for each input queue
	for(uint32_t iClient = 0; iClient < receivedPerClient.size(); ++iClient) {	// Process received packets.
		::bba::TUDPReceiveQueue											& clientReceived			= receivedPerClient[iClient];
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

	::sendGeneratedResponses(serverAsync);
	return 0;
}
