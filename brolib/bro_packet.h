#include "gpk_http.h"

#ifndef BRO_PACKET_H_230498209837
#define BRO_PACKET_H_230498209837

namespace bro
{
	struct SRequestHeader {
		::gpk::HTTP_METHOD						Method	;
		::gpk::view_const_string				Path	;
	};
} // namespace

#endif // BRO_PACKET_H_230498209837
