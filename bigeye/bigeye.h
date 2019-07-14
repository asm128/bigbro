#include "gpk_json.h"
#include "gpk_udp_client.h"

#ifndef BIGEYE_H_641651368135135
#define BIGEYE_H_641651368135135

namespace bro
{
	struct SBigEye {
		::gpk::SUDPClient						Client						= {};
		::gpk::SJSONFile						Config						= {};
	};

	::gpk::error_t							bigEyeInit					(::bro::SBigEye & app, const ::gpk::view_const_string & fileNameJSONConfig);

} // namespace

#endif // BIGEYE_H_641651368135135
