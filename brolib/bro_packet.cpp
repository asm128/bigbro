#include "bro_packet.h"

::gpk::error_t				bro::requestWrite			(::bro::SRequestPacket & headerToWrite, ::gpk::array_pod<byte_t> & output)	{ 
	output.append(::gpk::view_const_byte{(const char*)&headerToWrite.Method, (uint32_t)sizeof(::gpk::HTTP_METHOD)});
	::gpk::viewWrite(headerToWrite.Path			, output);
	::gpk::viewWrite(headerToWrite.QueryString	, output);
	::gpk::viewWrite(headerToWrite.ContentBody	, output);
	return 0; 
}

::gpk::error_t				bro::requestRead			(::bro::SRequestPacket & headerToRead, const ::gpk::view_const_char & input	)	{ 
	uint32_t						offset						= 0;
	headerToRead.Method			= *(::gpk::HTTP_METHOD*)&input[offset]; 
	offset						+= sizeof(::gpk::HTTP_METHOD);
	offset						+= ::gpk::viewRead(headerToRead.Path		, {&input[offset], input.size() - offset});
	offset						+= ::gpk::viewRead(headerToRead.QueryString	, {&input[offset], input.size() - offset});
	offset						+= ::gpk::viewRead(headerToRead.ContentBody	, {&input[offset], input.size() - offset});
	return 0; 
}
