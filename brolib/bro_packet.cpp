#include "bro_packet.h"

template<typename _tElement>
::gpk::error_t				viewWrite					(const ::gpk::view_array<const _tElement>& headerToWrite, ::gpk::array_pod<byte_t>	& output)	{ 
	output.append(::gpk::view_const_char{(const char*)&headerToWrite.size(), (uint32_t)sizeof(uint32_t)}); 
	output.append(::gpk::view_const_char{(const char*)headerToWrite.begin(), headerToWrite.size() * (uint32_t)sizeof(_tElement)});
	return sizeof(uint32_t) + headerToWrite.size();
}

template<typename _tElement>
::gpk::error_t				viewRead					(::gpk::view_array<const _tElement> & headerToRead, const ::gpk::view_const_char	& input	)	{ 
	headerToRead				= {(const _tElement*)&input[sizeof(uint32_t)], *(uint32_t*)input.begin()}; 
	return sizeof(uint32_t) + headerToRead.size() * sizeof(_tElement);
}

::gpk::error_t				bro::requestWrite			(::bro::SRequestHeader & headerToWrite, ::gpk::array_pod<byte_t>		& output)	{ 
	output.append(::gpk::view_const_char{(const char*)&headerToWrite.Method, (uint32_t)sizeof(::gpk::HTTP_METHOD)});
	::viewWrite(headerToWrite.Path			, output);
	::viewWrite(headerToWrite.QueryString	, output);
	::viewWrite(headerToWrite.ContentBody	, output);
	return 0; 
}

::gpk::error_t				bro::requestRead			(::bro::SRequestHeader & headerToRead, const ::gpk::view_const_char	& input	)	{ 
	uint32_t						offset						= 0;
	headerToRead.Method			= *(::gpk::HTTP_METHOD*)&input[offset]; 
	offset						+= sizeof(::gpk::HTTP_METHOD);
	offset						+= ::viewRead(headerToRead.Path		, {&input[offset], input.size() - offset});
	offset						+= ::viewRead(headerToRead.QueryString, {&input[offset], input.size() - offset});
	offset						+= ::viewRead(headerToRead.ContentBody, {&input[offset], input.size() - offset});
	return 0; 
}
