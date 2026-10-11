#include "llc_json.h"
#include "llc_udp_client.h"
#include "bro_packet.h"

#ifndef BIGEYE_H_641651368135135
#define BIGEYE_H_641651368135135

namespace bro
{
	struct SBigMan {
		::llc::SUDPClient						Client						= {};
		::llc::SJSONFile						Config						= {};
	};

	::llc::error_t							bigEyeLoadConfig			(::bro::SBigMan & app, const ::llc::view_const_string & fileNameJSONConfig);

} // namespace

#endif // BIGEYE_H_641651368135135
