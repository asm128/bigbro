#include "bigbro.h"

#ifndef RAZOR_H_20190712
#define RAZOR_H_20190712

namespace razor
{
	struct SRazorApp {
		::bro::SBigBro								BigBro						= {};
		::gpk::SJSONFile							Config						= {};
	};

	::gpk::error_t								loadDetail					(const ::gpk::view_array<::gpk::TKeyValConstString> & environViews, int32_t & detail);
	::gpk::error_t								processQuery						
		( const ::gpk::view_array<const ::bro::TKeyValJSONDB>	& databases
		, const ::bro::SQuery									& query
		, const ::gpk::view_const_string						& databaseName
		, int32_t												detail
		, ::gpk::array_pod<char_t>								& output
		);
}

#endif // RAZOR_H_20190712
