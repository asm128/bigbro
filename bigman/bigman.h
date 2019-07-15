#include "gpk_json.h"
#include "gpk_udp_client.h"
#include "bro_packet.h"

#ifndef BIGEYE_H_641651368135135
#define BIGEYE_H_641651368135135

namespace bro
{
	struct SBigMan {
		::gpk::SUDPClient						Client						= {};
		::gpk::SJSONFile						Config						= {};
	};

	::gpk::error_t							bigEyeLoadConfig			(::bro::SBigMan & app, const ::gpk::view_const_string & fileNameJSONConfig);

} // namespace

#endif // BIGEYE_H_641651368135135
