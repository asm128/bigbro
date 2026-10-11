#include "bigbro.h"

#ifndef RAZOR_H_20190712
#define RAZOR_H_20190712

namespace razor
{
	struct SRazorAppV0 {
		::bro::SBigBroV0							BigBro						= {};
		::llc::SJSONFile							Config						= {};
	};

	//struct SRazorAppV1 {
	//	::bro::SBigBroV1							BigBro						= {};
	//	::llc::SJSONFile							Config						= {};
	//};
	//
	::llc::error_t								loadConfig					(::razor::SRazorAppV0 & appState, const ::llc::view_const_string & jsonFileName, const ::llc::view_array<::llc::TKeyValConstString> & queryString, const ::llc::view_array<::llc::TKeyValConstString> & environViews);
	::llc::error_t								processQuery						
		( ::llc::array_obj<::bro::TKeyValJSONDBV0>	& databases
		, const ::bro::SQuery						& query
		, const ::llc::view_const_string			& databaseName
		, ::llc::array_pod<char_t>					& output
		);
}

#endif // RAZOR_H_20190712
