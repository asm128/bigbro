#include "bigbro.h"

#include <Windows.h>
#include <process.h>

#ifndef RAZOR_H_20190712
#define RAZOR_H_20190712

namespace razor
{
	struct SProcess {
		PROCESS_INFORMATION							ProcessInfo					= {}; 
		STARTUPINFOA								StartInfo					= {sizeof(STARTUPINFOA)};
	};

	struct SRazorApp {
		::bro::SBigBro								BigBro						= {};
		::razor::SProcess							Process						= {};
		::gpk::SJSONFile							Config						= {};
	};

	::gpk::error_t									loadCWD						(const ::gpk::view_array<::gpk::TKeyValConstString> & environViews, ::gpk::array_pod<char_t> & method);
	::gpk::error_t									loadDetail					(const ::gpk::view_array<::gpk::TKeyValConstString> & environViews, int32_t & detail);
}


#endif // RAZOR_H_20190712
