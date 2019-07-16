#include "gpk_http.h"
#include "gpk_array.h"

#ifndef BRO_PACKET_H_230498209837
#define BRO_PACKET_H_230498209837

namespace bro
{
	struct SRequestPacket {
		::gpk::HTTP_METHOD						Method		;
		::gpk::view_const_char					Path		;
		::gpk::view_const_char					QueryString	;
		::gpk::view_const_char					ContentBody	;
	};

	::gpk::error_t			requestWrite	(::bro::SRequestPacket & headerToRead, ::gpk::array_pod<byte_t>		& output);
	::gpk::error_t			requestRead		(::bro::SRequestPacket & headerToRead, const ::gpk::view_const_char	& input	);
} // namespace

#endif // BRO_PACKET_H_230498209837
