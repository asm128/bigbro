#include "gpk_udp_server.h"

#include "gpk_framework.h"

#ifndef APPLICATION_H_2078934982734
#define APPLICATION_H_2078934982734

namespace bro // I'm gonna use a different namespace in order to test a few things about the macros.
{

	typedef ::gpk::array_obj<::gpk::ptr_obj<::gpk::SUDPConnectionMessage>>			TUDPReceiveQueue;
	typedef ::gpk::array_obj<::gpk::array_pod<char_t>>								TUDPResponseQueue;

	struct SServerAsync {
		::gpk::SUDPServer																UDPServer							= {};
		::gpk::array_obj<::bro::TUDPReceiveQueue>										ReceivedPerClient					= {};
		::gpk::array_obj<::bro::TUDPResponseQueue>										ClientResponses						= {};
	};

	struct SJSONDatabase {
		::gpk::SJSONFile																Table;
		::gpk::array_obj<::gpk::view_const_string>										Bindings;
	};

	typedef ::gpk::SKeyVal<::gpk::view_const_string, ::bro::SJSONDatabase>					TKeyValJSONDB;
	typedef ::gpk::SKeyVal<::gpk::view_const_string, ::gpk::ptr_obj<::bro::SServerAsync>>	TKeyValServerAsync;
	typedef ::gpk::SRenderTarget<::gpk::SColorBGRA, uint32_t>								TRenderTarget;

	struct SApplication {
		::gpk::SFramework																Framework;
		::gpk::ptr_obj<::bro::TRenderTarget>											Offscreen							= {};

		::bro::SServerAsync																ServerAsync							= {};
		::gpk::array_obj<::bro::TKeyValServerAsync>										Servers								= {};
		::gpk::array_obj<::bro::TKeyValJSONDB>											Databases							= {};

		uint16_t																		BasePort							= 0;
		int16_t																			Adapter								= 0;

		int32_t																			IdExit								= -1;

		::std::mutex																	LockGUI;
		::std::mutex																	LockRender;

																						SApplication		(::gpk::SRuntimeValues& runtimeValues)	: Framework(runtimeValues, "bigbro.json")	{}
	};
} // namespace

#endif // APPLICATION_H_2078934982734
