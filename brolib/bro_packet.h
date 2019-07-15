#include "gpk_http.h"
#include "gpk_array.h"

#ifndef BRO_PACKET_H_230498209837
#define BRO_PACKET_H_230498209837

namespace bro
{
	struct SRequestHeader {
		::gpk::HTTP_METHOD						Method		;
		::gpk::view_const_string				Path		;
		::gpk::view_const_string				QueryString	;
		::gpk::view_const_string				ContentBody	;
	};

	::gpk::error_t			requestWrite	(SRequestHeader & headerToRead, ::gpk::array_pod<byte_t>		& output);
	::gpk::error_t			requestRead		(SRequestHeader & headerToRead, const ::gpk::view_const_char	& input	);
} // namespace

#endif // BRO_PACKET_H_230498209837
