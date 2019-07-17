#include "bigbro.h"

#include "gpk_framework.h"
#include "gpk_udp_server.h"

#ifndef APPLICATION_H_2078934982734
#define APPLICATION_H_2078934982734

namespace bba // bigbroapp
{
	typedef ::gpk::array_obj<::gpk::ptr_obj<::gpk::SUDPConnectionMessage>>	TUDPReceiveQueue;
	typedef ::gpk::array_obj<::gpk::array_pod<char_t>>						TUDPResponseQueue;

	GDEFINE_ENUM_TYPE	(CONNECTION_STATE, uint8_t);
	GDEFINE_ENUM_VALUE	(CONNECTION_STATE, IDLE			, 0);
	GDEFINE_ENUM_VALUE	(CONNECTION_STATE, PROCESSING	, 1);
	struct SServerAsync {
		::gpk::SUDPServer														UDPServer							= {};
		::gpk::array_obj<::bba::TUDPReceiveQueue>								ReceivedPerClient					= {};
		::gpk::array_obj<::bba::TUDPResponseQueue>								ClientResponses						= {};
		::gpk::array_obj<::bba::TUDPResponseQueue>								PartialResults						= {};
		::gpk::array_obj<::gpk::array_pod<CONNECTION_STATE>>					RequestStates						= {};
	};

	typedef ::gpk::SKeyVal<::gpk::view_const_string, ::gpk::ptr_obj<::bba::SServerAsync>>	
																			TKeyValServerAsync;
	typedef ::gpk::SRenderTarget<::gpk::SColorBGRA, uint32_t>				TRenderTarget;

	struct SApplication {
		::gpk::SFramework														Framework;
		::gpk::ptr_obj<::bba::TRenderTarget>									Offscreen							= {};

		::bro::SBigBroV0															BigBro								= {};
		::bba::SServerAsync														ServerAsync							= {};
		::gpk::array_obj<::bba::TKeyValServerAsync>								Servers								= {};

		uint16_t																BasePort							= 0;
		int16_t																	Adapter								= 0;

		int32_t																	IdExit								= -1;

		::std::mutex															LockGUI;
		::std::mutex															LockRender;

																				SApplication						(::gpk::SRuntimeValues& runtimeValues)	: Framework(runtimeValues, "bigbro.json")	{}
	};

	::gpk::error_t															loadConfig							(::bba::SApplication & app);
	::gpk::error_t															updateCRUDServer					(::bro::SBigBroV0 & appState, ::bba::SServerAsync & serverAsync);
} // namespace


#endif // APPLICATION_H_2078934982734
