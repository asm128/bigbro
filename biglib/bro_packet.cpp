#include "bro_packet.h"

::llc::error_t				bro::requestWrite			(::bro::SRequestPacket & headerToWrite, ::llc::array_pod<byte_t> & output)	{ 
	output.append(::llc::view_const_byte{(const char*)&headerToWrite.Method, (uint32_t)sizeof(::llc::HTTP_METHOD)});
	::llc::viewWrite(headerToWrite.Path			, output);
	::llc::viewWrite(headerToWrite.QueryString	, output);
	::llc::viewWrite(headerToWrite.ContentBody	, output);
	return 0; 
}

::llc::error_t				bro::requestRead			(::bro::SRequestPacket & headerToRead, const ::llc::view_const_char & input	)	{ 
	uint32_t						offset						= 0;
	headerToRead.Method			= *(::llc::HTTP_METHOD*)&input[offset]; 
	offset						+= sizeof(::llc::HTTP_METHOD);
	offset						+= ::llc::viewRead(headerToRead.Path		, {&input[offset], input.size() - offset});
	offset						+= ::llc::viewRead(headerToRead.QueryString	, {&input[offset], input.size() - offset});
	offset						+= ::llc::viewRead(headerToRead.ContentBody	, {&input[offset], input.size() - offset});
	return 0; 
}
