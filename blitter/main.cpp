#define GPK_CONSOLE_LOG_ENABLED
#define GPK_ERROR_PRINTF_ENABLED
#define GPK_WARNING_PRINTF_ENABLED
#define GPK_INFO_PRINTF_ENABLED

#include "gpk_log.h"
#include "gpk_storage.h"
#include "gpk_json.h"
#include "gpk_parse.h"
#include "gpk_find.h"
#include "gpk_deflate.h"

#include "bigbro.h"

static constexpr const uint32_t			DEFAULT_BLOCK_SIZE				= 1024;

::gpk::error_t							jsonArraySplit					(const ::gpk::SJSONNode & jsonArrayToSplit, const ::gpk::view_array<::gpk::view_const_string> & jsonViews, const uint32_t blockSize, ::gpk::array_obj<::gpk::array_pod<char_t>> & outputJsons)		{
	const uint32_t								remainder						= jsonArrayToSplit.Children.size() % blockSize;
	const uint32_t								countParts						= jsonArrayToSplit.Children.size() / blockSize + one_if(remainder);
	gpk_necall(outputJsons.resize(countParts), "%s", "Out of memory?");
	uint32_t									iSourceRecord					= 0;
	for(uint32_t iPart = 0; iPart < outputJsons.size(); ++iPart) {
		::gpk::array_pod<char_t>					& outputJson					= outputJsons[iPart];
		gpk_necall(outputJson.push_back('['), "%s", "Out of memory?");
		for(uint32_t iPartRecord = 0, countPartRecords = (remainder && iPart == countParts - 1) ? remainder : blockSize
			; iPartRecord < countPartRecords
			; ++iPartRecord) {
			gpk_necall(::gpk::jsonWrite(jsonArrayToSplit.Children[iSourceRecord++], jsonViews, outputJson), "%s", "Unknown error!");;
			if(iPartRecord < countPartRecords - 1)
				gpk_necall(outputJson.push_back(','), "%s", "Out of memory?");
		}
		gpk_necall(outputJson.push_back(']'), "%s", "Out of memory?");
	}
	return 0;
}

struct SSplitParams {
	::gpk::view_const_string				FileNameSrc						= {};	// First parameter is the only parameter, which is the name of the source file to be split.
	::gpk::view_const_string				PathWithoutExtension			= {};	// First parameter is the only parameter, which is the name of the source file to be split.
	::gpk::view_const_string				DBName							= {};	// First parameter is the only parameter, which is the name of the source file to be split.
	::gpk::view_const_string				EncryptionKey					= {};	// First parameter is the only parameter, which is the name of the source file to be split.

	uint32_t								BlockSize						= 0;
	bool									DeflatedOutput					= false;
};

int										loadParams						(SSplitParams& params, int argc, char ** argv)		{
	for(int32_t iArg = 5; iArg < argc; ++iArg)
		info_printf("Unknown parameter: %s.", argv[iArg]);
	ree_if(2 > argc, "Usage:\n\t%s [filename] [blockSize] [deflated output (1:0)] [deflated input (1:0)] ", argv[0]);
	ree_if(65535 < argc, "Invalid parameter count: %u.", (uint32_t)argc);
	params.FileNameSrc						= {argv[1], (uint32_t)-1};	// First parameter is the only parameter, which is the name of the source file to be split.
	if(argc > 2) {	// load block size param
		::gpk::parseIntegerDecimal({argv[2], (uint32_t)-1}, &params.BlockSize);
		info_printf("Using block size: %u.", params.BlockSize);
	}
	params.DeflatedOutput					= (argc >  3 && argv[3][0] != '0');
	if(argc >  4)
		params.EncryptionKey					= {argv[4], (uint32_t)-1};
	//params.DeflatedInput					= (argc >  4 && argv[4][0] != '0');
	if(0 == params.BlockSize)
		params.BlockSize						= ::DEFAULT_BLOCK_SIZE;

	::gpk::error_t								indexOfDot						= ::gpk::rfind('.', params.FileNameSrc);
	::gpk::error_t								indexOfLastSlash				= ::gpk::findLastSlash(params.FileNameSrc);
	params.PathWithoutExtension				= (indexOfDot > indexOfLastSlash) ? ::gpk::view_const_string{params.FileNameSrc.begin(), (uint32_t)indexOfDot} : params.FileNameSrc;
	params.DBName							= (-1 == indexOfLastSlash) 
		? params.PathWithoutExtension
		: ::gpk::view_const_string{&params.PathWithoutExtension[indexOfLastSlash], params.PathWithoutExtension.size() - indexOfLastSlash}
		;	// First parameter is the only parameter, which is the name of the source file to be split.

	info_printf("Deflated output: %s", params.DeflatedOutput ? "true" : "false");
	return 0;
}

// Splits a file into file.split.## parts.
::gpk::error_t							setUpFolder						(SSplitParams& params, ::gpk::array_pod<char_t> & dbFolderName)		{
	char										folderNameDigits	[32]		= {};
	sprintf_s(folderNameDigits, ".%u.db/", params.BlockSize);
	gpk_necall(dbFolderName.append(::gpk::view_const_string{"./"})				, "%s", "Out of memory?");
	gpk_necall(dbFolderName.append(params.PathWithoutExtension)					, "%s", "Out of memory?");
	gpk_necall(dbFolderName.append(::gpk::view_const_string{folderNameDigits})	, "%s", "Out of memory?");
	gpk_necall(::gpk::pathCreate({dbFolderName.begin(), dbFolderName.size()}), "Failed to create database folder: %s.", dbFolderName.begin());
	info_printf("Output folder: %s.", dbFolderName.begin());
	return 0;
}

// Splits a file into file.split.## parts.
int										main							(int argc, char ** argv)		{
	SSplitParams								params							= {};
	gpk_necall(::loadParams(params, argc, argv), "%s", "");
	::gpk::array_pod<char_t>					dbFolderName					= {};
	gpk_necall(::setUpFolder(params, dbFolderName), "Failed to creat database folder for database file: '%s'.", params.FileNameSrc.begin());

	::gpk::SJSONFile							jsonFileToSplit					= {};
	gpk_necall(::gpk::jsonFileRead(jsonFileToSplit, params.FileNameSrc), "Failed to load file: %s.", params.FileNameSrc.begin());

	::gpk::array_obj<::gpk::array_pod<char_t>>	outputJsons;
	ree_if(0 == jsonFileToSplit.Reader.Tree.size() || jsonFileToSplit.Reader.Object[0].Type != ::gpk::JSON_TYPE_ARRAY, "Invalid input format. %s", "JSON contents not an array.");
	gpk_necall(::jsonArraySplit(*jsonFileToSplit.Reader.Tree[0], jsonFileToSplit.Reader.View , params.BlockSize, outputJsons), "%s", "Unknown error!");

	::gpk::array_pod<char_t>					partFileName					= {};
	::gpk::array_pod<char_t>					deflated						= {};
	for(uint32_t iPart = 0; iPart < outputJsons.size(); ++iPart) {
		const ::gpk::array_pod<char_t>				& partBytes						= outputJsons[iPart];
		::bro::blockFileName(partFileName, params.DBName, params.EncryptionKey, params.DeflatedOutput ? ::bro::DATABASE_HOST_DEFLATE : ::bro::DATABASE_HOST_LOCAL, iPart);
		info_printf("Saving part file to disk: '%s'.", partFileName.begin());
		if(false == params.DeflatedOutput)
			gpk_necall(::gpk::fileFromMemory({partFileName.begin(), partFileName.size()}, partBytes), "Failed to write part: %u.", iPart);
		else {
			gpk_necall(deflated.append((char*)&partBytes.size(), sizeof(uint32_t)), "%s", "Out of memory?");;
			gpk_necall(::gpk::arrayDeflate(partBytes, deflated), "Failed to deflate part: %u.", iPart);
			gpk_necall(::gpk::fileFromMemory({partFileName.begin(), partFileName.size()}, deflated), "Failed to write part: %u.", iPart);
			deflated.clear();
		}
	}
	return 0; 
}