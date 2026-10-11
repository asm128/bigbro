#include "llc_http.h"
#include "llc_array.h"

#ifndef BRO_PACKET_H_230498209837
#define BRO_PACKET_H_230498209837

namespace bro
{
	struct SRequestPacket {
		::llc::HTTP_METHOD						Method		;
		::llc::view_const_char					Path		;
		::llc::view_const_char					QueryString	;
		::llc::view_const_char					ContentBody	;
	};

	::llc::error_t			requestWrite	(::bro::SRequestPacket & headerToRead, ::llc::array_pod<byte_t>		& output);
	::llc::error_t			requestRead		(::bro::SRequestPacket & headerToRead, const ::llc::view_const_char	& input	);
} // namespace

#endif // BRO_PACKET_H_230498209837
