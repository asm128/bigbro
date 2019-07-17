#include "bigbro.h"

#ifndef RAZOR_H_20190712
#define RAZOR_H_20190712

namespace razor
{
	struct SRazorApp {
		::bro::SBigBro								BigBro						= {};
		::gpk::SJSONFile							Config						= {};
	};

	::gpk::error_t								loadConfig					(::razor::SRazorApp & appState, const ::gpk::view_array<::gpk::TKeyValConstString> & queryString);
	::gpk::error_t								processQuery						
		( const ::gpk::view_array<const ::bro::TKeyValJSONDB>	& databases
		, const ::bro::SQuery									& query
		, const ::gpk::view_const_string						& databaseName
		, ::gpk::array_pod<char_t>								& output
		);
}

#endif // RAZOR_H_20190712
