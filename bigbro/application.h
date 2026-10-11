#include "bigbro.h"

#include "llc_framework.h"
#include "llc_udp_server.h"

#ifndef APPLICATION_H_2078934982734
#define APPLICATION_H_2078934982734

namespace bba // bigbroapp
{
	typedef ::llc::array_obj<::llc::ptr_obj<::llc::SUDPConnectionMessage>>	TUDPReceiveQueue;
	typedef ::llc::array_obj<::llc::array_pod<char_t>>						TUDPResponseQueue;

	GDEFINE_ENUM_TYPE	(CONNECTION_STATE, uint8_t);
	GDEFINE_ENUM_VALUE	(CONNECTION_STATE, IDLE			, 0);
	GDEFINE_ENUM_VALUE	(CONNECTION_STATE, PROCESSING	, 1);
	struct SServerAsync {
		::llc::SUDPServer														UDPServer							= {};
		::llc::array_obj<::bba::TUDPReceiveQueue>								ReceivedPerClient					= {};
		::llc::array_obj<::bba::TUDPResponseQueue>								ClientResponses						= {};
		::llc::array_obj<::bba::TUDPResponseQueue>								PartialResults						= {};
		::llc::array_obj<::llc::array_pod<CONNECTION_STATE>>					RequestStates						= {};
	};

	typedef ::llc::SKeyVal<::llc::view_const_string, ::llc::ptr_obj<::bba::SServerAsync>>	
																			TKeyValServerAsync;
	typedef ::llc::SRenderTarget<::llc::SColorBGRA, uint32_t>				TRenderTarget;

	struct SApplication {
		::llc::SFramework														Framework;
		::llc::ptr_obj<::bba::TRenderTarget>									Offscreen							= {};

		::bro::SBigBroV0															BigBro								= {};
		::bba::SServerAsync														ServerAsync							= {};
		::llc::array_obj<::bba::TKeyValServerAsync>								Servers								= {};

		uint16_t																BasePort							= 0;
		int16_t																	Adapter								= 0;

		int32_t																	IdExit								= -1;

		::std::mutex															LockGUI;
		::std::mutex															LockRender;

																				SApplication						(::llc::SRuntimeValues& runtimeValues)	: Framework(runtimeValues, "bigbro.json")	{}
	};

	::llc::error_t															loadConfig							(::bba::SApplication & app);
	::llc::error_t															updateCRUDServer					(::bro::SBigBroV0 & appState, ::bba::SServerAsync & serverAsync);
} // namespace


#endif // APPLICATION_H_2078934982734
