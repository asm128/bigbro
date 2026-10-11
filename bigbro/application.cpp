#include "application.h"

#include "bro_packet.h"

#include "llc_tcpip.h"
#include "llc_find.h"
#include "llc_process.h"

#include "llc_parse.h"
#include "llc_cgi.h"
#include "llc_stdstring.h"


static	::llc::error_t										loadServerConfig			(::bba::SApplication & app)						{
	::llc::SFramework												& framework					= app.Framework;
	uint64_t														port						= 9998;
	uint64_t														adapter						= 0;
	{ // load port from config file
		::llc::view_const_string										jsonResult					= {};
		const ::llc::SJSONReader										& jsonReader				= framework.JSONConfig.Reader;
		const int32_t													indexObjectApp				= ::llc::jsonExpressionResolve("application.bigbro", jsonReader, 0, jsonResult);
		gwarn_if(errored(indexObjectApp), "Failed to find application node (%s) in json configuration file: '%s'", "application.bigbro", framework.FileNameJSONConfig.begin())
		else {
			jsonResult													= "";
			gwarn_if(errored(::llc::jsonExpressionResolve("listen_port", jsonReader, indexObjectApp, jsonResult)), "Failed to load config from json! Last contents found: %s.", jsonResult.begin()) 
			else {
				::llc::parseIntegerDecimal(jsonResult, &port);
				info_printf("Port to listen on: %u.", (uint32_t)port);
			}
			jsonResult													= "";
			gwarn_if(errored(::llc::jsonExpressionResolve("adapter", jsonReader, indexObjectApp, jsonResult)), "Failed to load config from json! Last contents found: %s.", jsonResult.begin()) 
			else {
				::llc::parseIntegerDecimal(jsonResult, &adapter);
				info_printf("Adapter: %u.", (uint32_t)adapter);
			}
		}
	}
	app.BasePort												= (uint16_t)port;
	app.Adapter													= (uint16_t)adapter;
	return 0;
}

::llc::error_t												bba::loadConfig					(::bba::SApplication & app)						{
	llc_necall(::loadServerConfig(app), "%s", "Error loading networking configuration.");
	llc_necall(::bro::configLoad(app.BigBro, app.Framework.JSONConfig.Reader), "%s", "Failed to load BigBro configuration.");
	return 0;
}


static	::llc::error_t										processPayload				(::bro::SBigBroV0 & appState, const ::llc::view_const_byte & payload, ::llc::array_pod<char_t> & partialResult, ::llc::array_pod<char_t> & bytesResponse)						{
	::bro::SRequestPacket											packetReceived;
	::bro::requestRead(packetReceived, payload);
	{	// --- Retrieve query from request.
		::llc::array_obj<::llc::TKeyValConstString>						qsKeyVals;
		::llc::array_obj<::llc::view_const_string>						queryStringElements			= {};
		::llc::querystring_split({packetReceived.QueryString.begin(), packetReceived.QueryString.size()}, queryStringElements);
		qsKeyVals.resize(queryStringElements.size());
		for(uint32_t iKeyVal = 0; iKeyVal < qsKeyVals.size(); ++iKeyVal) {
			::llc::TKeyValConstString										& keyValDst					= qsKeyVals[iKeyVal];
			::llc::keyval_split(queryStringElements[iKeyVal], keyValDst);
		}
		::bro::queryLoad(appState.Query, qsKeyVals);
	}
	// --- Generate response
	::llc::view_const_string										dbName						= (packetReceived.Path.size() > 1) ? ::llc::view_const_string{&packetReceived.Path[1], packetReceived.Path.size() - 1} : ::llc::view_const_string{};;
	uint64_t														detail						= (uint64_t)-1LL;
	{	// --- Retrieve detail part 
		::llc::view_const_string										strDetail					= {};
		const ::llc::error_t											indexOfLastBar				= ::llc::rfind('/', dbName);
		const uint32_t													startOfDetail				= (uint32_t)(indexOfLastBar + 1);
		if(indexOfLastBar > 0 && startOfDetail < dbName.size()) {
			strDetail													= {&dbName[startOfDetail], dbName.size() - startOfDetail};
			dbName														= {dbName.begin(), (uint32_t)indexOfLastBar};
			if(strDetail.size()) {
				::llc::stoull(strDetail, &detail);
				appState.Query.Detail										= (int64_t)detail;
			}
		}
	}
	if(0 != dbName.size()) {
		::llc::array_obj<::bro::TCacheMissRecord>						cacheMisses;
		::bro::generate_output_for_db(appState.Databases, appState.Query, dbName, partialResult, cacheMisses);
		if(0 == cacheMisses.size()) {
			bytesResponse.append(partialResult);
			partialResult.clear();
		}
		else {
			char format[256];
			bytesResponse.clear();
			::llc::array_obj<::bro::TCacheMissRecord>		cacheMissesFolded;
			for(uint32_t iAliasMiss = 0; iAliasMiss < cacheMisses.size(); ++iAliasMiss) {
				const ::bro::TCacheMissRecord								& miss			= cacheMisses[iAliasMiss];
				cacheMissesFolded.push_back({miss.Key, {}});
				for(uint32_t iMiss = 0; iMiss < miss.Val.size(); ++iMiss) {
					bool														bFolded			= false;
					for(uint32_t iFolded = 0; iFolded < cacheMissesFolded.size(); ++iFolded) { 
						const ::bro::TCacheMissRecord								& missFolded	= cacheMissesFolded[iFolded];
						for(uint32_t iFoldedMiss = 0; iFoldedMiss < cacheMissesFolded[iFolded].Val.size(); ++iFoldedMiss) { 
							if(miss.Val[iMiss] == missFolded.Val[iFoldedMiss]) {
								bFolded					= true;
								break;
							}
						}
					}
					if(bFolded)
						continue;
					cacheMissesFolded.push_back(miss);
				}
			}
			for(uint32_t iAliasMiss = 0; iAliasMiss < cacheMissesFolded.size(); ++iAliasMiss) {
				const ::bro::TCacheMissRecord					& missFolded			= cacheMissesFolded[iAliasMiss];
				for(uint32_t iMiss = 0; iMiss < missFolded.Val.size(); ++iMiss) {
					sprintf_s(format, "Cache Miss: %%.%us[%lli]", missFolded.Key.size(), missFolded.Val[iMiss]);
					info_printf(format, missFolded.Key.begin());
				}
			}
		}
	}
	return 0;
}

// Pick up messages for later processing in order to clear receive queues to avoid the connection's extra work.
static	::llc::error_t										pickUpQueueReceived			(::bba::SServerAsync & serverAsync)						{
	::llc::array_obj<::bba::TUDPReceiveQueue>						& receivedPerClient			= serverAsync.ReceivedPerClient;
	::llc::array_obj<::llc::array_pod<::bba::CONNECTION_STATE>>		& requestStates				= serverAsync.RequestStates;
	{
		::llc::mutex_guard												lock						(serverAsync.UDPServer.Mutex);
		receivedPerClient	.resize(serverAsync.UDPServer.Clients.size());
		requestStates		.resize(serverAsync.UDPServer.Clients.size(), ::bba::CONNECTION_STATE_IDLE);
		for(uint32_t iClient = 0; iClient < serverAsync.UDPServer.Clients.size(); ++iClient) {
			::llc::ptr_obj<::llc::SUDPConnection>							conn						= serverAsync.UDPServer.Clients[iClient];
			::llc::mutex_guard												lockRecv					(conn->Queue.MutexReceive);
			receivedPerClient[iClient]									= conn->Queue.Received;
			conn->Queue.Received.clear();
		}
	}
	return 0;
}

// Send generated responses 
static	::llc::error_t										sendGeneratedResponses		(::bba::SServerAsync & serverAsync)						{
	::llc::array_obj<::bba::TUDPResponseQueue>						& clientResponses			= serverAsync.ClientResponses;
	::llc::array_obj<::bba::TUDPReceiveQueue>						& receivedPerClient			= serverAsync.ReceivedPerClient;
	for(uint32_t iClient = 0; iClient < clientResponses.size(); ++iClient) {
		for(uint32_t iMessage = 0; iMessage < clientResponses[iClient].size(); ++iMessage) { // Send generated responses 
			const ::llc::view_const_byte									message						= clientResponses[iClient][iMessage];
			if(0 == message.size()) 
				continue;
			::llc::mutex_guard												lock						(serverAsync.UDPServer.Mutex);
			::llc::ptr_obj<::llc::SUDPConnection>							conn						= serverAsync.UDPServer.Clients[iClient];
			::llc::connectionPushData(*conn, conn->Queue, message, true, true, 10);
			receivedPerClient[iClient][iMessage]						= {};	// Clear received message.
		}
	}
	return 0;
}

::llc::error_t												bba::updateCRUDServer		(::bro::SBigBroV0 & appState, ::bba::SServerAsync & serverAsync)						{
	::pickUpQueueReceived(serverAsync);

	::llc::array_obj<::bba::TUDPReceiveQueue>						& receivedPerClient			= serverAsync.ReceivedPerClient;
	::llc::array_obj<::bba::TUDPResponseQueue>						& clientResponses			= serverAsync.ClientResponses;
	::llc::array_obj<::bba::TUDPResponseQueue>						& partialResults			= serverAsync.PartialResults;
	clientResponses		.resize(receivedPerClient.size());	// we need one output queue for each input queue
	partialResults		.resize(receivedPerClient.size());	// we need one output queue for each input queue
	for(uint32_t iClient = 0; iClient < receivedPerClient.size(); ++iClient) {	// Process received packets.
		::bba::TUDPReceiveQueue											& clientReceived			= receivedPerClient[iClient];
		clientResponses	[iClient].resize(clientReceived.size());		// we need one output message for each received message
		partialResults	[iClient].resize(clientReceived.size());		// we need one output message for each received message
		for(uint32_t iMessage = 0; iMessage < clientReceived.size(); ++iMessage) {
			info_printf("Client %i received: %s.", iClient, clientReceived[iMessage]->Payload.begin());	
			::llc::view_const_byte											payload						= clientReceived[iMessage]->Payload;
			::llc::array_pod<byte_t>										& bytesResponse				= clientResponses[iClient][iMessage];
			::llc::array_pod<byte_t>										& partialResult				= partialResults[iClient][iMessage];
			bytesResponse												= ::llc::view_const_string{"\r\n"};
			::processPayload(appState, payload, partialResult, bytesResponse);
			if(2 == bytesResponse.size() && 0 == partialResult.size())
				bytesResponse.append(::llc::view_const_string{"{}"});
		}
	}

	::sendGeneratedResponses(serverAsync);
	return 0;
}
