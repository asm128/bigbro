#include "razor.h"

#include "gpk_stdstring.h"
#include "gpk_process.h"
#include "gpk_storage.h"

#include "gpk_json_expression.h"

::gpk::error_t									razor::loadCWD							(const ::gpk::view_array<::gpk::TKeyValConstString> & environViews, ::gpk::array_pod<char_t> & cwd)	{
	for(uint32_t iKey = 0; iKey < environViews.size(); ++iKey) {
		if(environViews[iKey].Key == ::gpk::view_const_string{"SCRIPT_FILENAME"}) {
			cwd = environViews[iKey].Val;
			int32_t lastBarIndex = ::gpk::findLastSlash({cwd.begin(), cwd.size()});
			if(-1 != lastBarIndex) {
				cwd[lastBarIndex]		= 0;
				cwd.resize(lastBarIndex);
				break;
			}
		}
	}
	return 0;
}

::gpk::error_t									razor::loadDetail						(const ::gpk::view_array<::gpk::TKeyValConstString> & environViews, int32_t & detail)	{
	for(uint32_t iKey = 0; iKey < environViews.size(); ++iKey) {
		if(environViews[iKey].Key == ::gpk::view_const_string{"PATH_INFO"}) {
			uint64_t _detail = (uint64_t)-1LL;
			::gpk::stoull({&environViews[iKey].Val[1], environViews[iKey].Val.size() - 1}, &_detail);
			detail = (int32_t)_detail;
		}
	}
	return 0;
}
