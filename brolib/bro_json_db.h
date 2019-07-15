#include "gpk_json.h"

#ifndef BRO_JSON_DB_H_029430293742
#define BRO_JSON_DB_H_029430293742

namespace bro
{
	struct SJSONDatabase {
		::gpk::SJSONFile														Table;
		::gpk::array_obj<::gpk::view_const_string>								Bindings;
	};

	typedef ::gpk::SKeyVal<::gpk::view_const_string, ::bro::SJSONDatabase>	TKeyValJSONDB;
}

#endif // BRO_JSON_DB_H_029430293742
