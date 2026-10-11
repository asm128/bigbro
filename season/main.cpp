#define LLC_CONSOLE_LOG_ENABLED
#define LLC_ERROR_PRINTF_ENABLED
#define LLC_WARNING_PRINTF_ENABLED
#define LLC_INFO_PRINTF_ENABLED

#include "llc_log.h"
#include "llc_storage.h"
#include "llc_json.h"
#include "llc_parse.h"
#include "llc_find.h"
#include "llc_deflate.h"
#include "llc_aes.h"
#include "llc_noise.h"

#include "bigbro.h"

static constexpr const uint32_t			DEFAULT_BLOCK_SIZE				= 1024;

::llc::error_t							jsonArraySplit					(const ::llc::SJSONNode & jsonArrayToSplit, const ::llc::view_array<::llc::view_const_string> & jsonViews, const uint32_t blockSize, ::llc::array_obj<::llc::array_pod<char_t>> & outputJsons)		{
	const uint32_t								remainder						= jsonArrayToSplit.Children.size() % blockSize;
	const uint32_t								countParts						= jsonArrayToSplit.Children.size() / blockSize + one_if(remainder);
	llc_necall(outputJsons.resize(countParts), "%s", "Out of memory?");
	uint32_t									iSourceRecord					= 0;
	for(uint32_t iPart = 0; iPart < outputJsons.size(); ++iPart) {
		::llc::array_pod<char_t>					& outputJson					= outputJsons[iPart];
		llc_necall(outputJson.push_back('['), "%s", "Out of memory?");
		for(uint32_t iPartRecord = 0, countPartRecords = (remainder && iPart == countParts - 1) ? remainder : blockSize
			; iPartRecord < countPartRecords
			; ++iPartRecord) {
			llc_necall(::llc::jsonWrite(jsonArrayToSplit.Children[iSourceRecord++], jsonViews, outputJson), "%s", "Unknown error!");;
			if(iPartRecord < countPartRecords - 1)
				llc_necall(outputJson.push_back(','), "%s", "Out of memory?");
		}
		llc_necall(outputJson.push_back(']'), "%s", "Out of memory?");
	}
	return 0;
}

struct SSplitParams {
	::llc::view_const_string				FileNameSrc						= {};	// First parameter is the only parameter, which is the name of the source file to be split.
	::llc::view_const_string				PathWithoutExtension			= {};	// First parameter is the only parameter, which is the name of the source file to be split.
	::llc::view_const_string				DBName							= {};	// First parameter is the only parameter, which is the name of the source file to be split.
	::llc::view_const_string				EncryptionKey					= {};	// First parameter is the only parameter, which is the name of the source file to be split.

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
		::llc::parseIntegerDecimal({argv[2], (uint32_t)-1}, &params.BlockSize);
		info_printf("Using block size: %u.", params.BlockSize);
	}
	params.DeflatedOutput					= (argc >  3 && argv[3][0] != '0');
	if(argc > 4)
		params.EncryptionKey					= {argv[4], (uint32_t)-1};

	if(0 == params.BlockSize)
		params.BlockSize						= ::DEFAULT_BLOCK_SIZE;

	::llc::error_t								indexOfDot						= ::llc::rfind('.', params.FileNameSrc);
	::llc::error_t								indexOfLastSlash				= ::llc::findLastSlash(params.FileNameSrc);
	params.PathWithoutExtension				= (indexOfDot > indexOfLastSlash) ? ::llc::view_const_string{params.FileNameSrc.begin(), (uint32_t)indexOfDot} : params.FileNameSrc;
	params.DBName							= (-1 == indexOfLastSlash) 
		? params.PathWithoutExtension
		: ::llc::view_const_string{&params.PathWithoutExtension[indexOfLastSlash], params.PathWithoutExtension.size() - indexOfLastSlash}
		;	// First parameter is the only parameter, which is the name of the source file to be split.

	info_printf("Deflated output: %s", params.DeflatedOutput ? "true" : "false");
	return 0;
}

// Splits a file.json into file.#blocksize.db/file.##.json parts.
int										main							(int argc, char ** argv)		{
	SSplitParams								params							= {};
	llc_necall(::loadParams(params, argc, argv), "%s", "");

	::llc::array_pod<char_t>					dbFolderName					= {};
	llc_necall(::bro::tableFolderName(dbFolderName, params.DBName, params.BlockSize), "%s", "??");
	llc_necall(::llc::pathCreate({dbFolderName.begin(), dbFolderName.size()}), "Failed to create database folder: %s.", dbFolderName.begin());
	info_printf("Output folder: %s.", dbFolderName.begin());
	if(dbFolderName.size() && dbFolderName[dbFolderName.size()-1] != '/' && dbFolderName[dbFolderName.size()-1] != '\\')
		llc_necall(dbFolderName.push_back('/'), "%s", "Out of memory?");
	else if(0 == dbFolderName.size())
		llc_necall(dbFolderName.append(::llc::view_const_string{"./"}), "%s", "Out of memory?");

	::llc::SJSONFile							jsonFileToSplit					= {};
	llc_necall(::llc::jsonFileRead(jsonFileToSplit, params.FileNameSrc), "Failed to load file: %s.", params.FileNameSrc.begin());
	ree_if(0 == jsonFileToSplit.Reader.Tree.size(), "Invalid input format. %s", "File content is not a JSON array.");
	ree_if(jsonFileToSplit.Reader.Object[0].Type != ::llc::JSON_TYPE_ARRAY, "Invalid input format. %s", ::llc::get_value_label(jsonFileToSplit.Reader.Object[0].Type).begin());

	::llc::array_obj<::llc::array_pod<char_t>>	outputJsons;
	llc_necall(::jsonArraySplit(*jsonFileToSplit.Reader.Tree[0], jsonFileToSplit.Reader.View , params.BlockSize, outputJsons), "%s", "Unknown error!");

	::llc::array_pod<char_t>					partFileName					= {};
	::llc::array_pod<char_t>					pathToWriteTo					= {};
	::llc::array_pod<char_t>					deflated						= {};
	::llc::array_pod<char_t>					encrypted						= {};
	::llc::array_pod<char_t>					verify							= {};
	for(uint32_t iPart = 0; iPart < outputJsons.size(); ++iPart) {
		::llc::array_pod<char_t>					& partBytes						= outputJsons[iPart];
		uint64_t									crcToStore						= 0;
		for(uint32_t i=0; i < partBytes.size(); ++i) 
			crcToStore								+= ::llc::noise1DBase(partBytes[i]);

		llc_necall(partBytes.append((char*)&crcToStore, sizeof(uint64_t)), "%s", "Out of memory?");;

		pathToWriteTo							= dbFolderName;
		llc_necall(::bro::blockFileName(partFileName, params.DBName, params.EncryptionKey, params.DeflatedOutput ? ::bro::DATABASE_HOST_DEFLATE : ::bro::DATABASE_HOST_LOCAL, iPart), "%s", "??");
		llc_necall(pathToWriteTo.append(partFileName), "%s", "Out of memory?");
		if(false == params.DeflatedOutput) {
			if(0 == params.EncryptionKey.size()) {
				info_printf("Saving part file to disk: '%s'. Size: %u.", pathToWriteTo.begin(), partBytes.size());
				llc_necall(::llc::fileFromMemory({pathToWriteTo.begin(), pathToWriteTo.size()}, partBytes), "Failed to write part: %u.", iPart);
			}
			else {
				llc_necall(::llc::aesEncode({partBytes.begin(), partBytes.size()}, params.EncryptionKey, ::llc::AES_LEVEL_256, encrypted), "Failed to encrypt part: %u.", iPart);
				info_printf("Saving part file to disk: '%s'. Size: %u.", pathToWriteTo.begin(), encrypted.size());
				llc_necall(::llc::fileFromMemory({pathToWriteTo.begin(), pathToWriteTo.size()}, encrypted), "Failed to write part: %u.", iPart);
				verify.clear();
				llc_necall(::llc::aesDecode(encrypted, params.EncryptionKey, ::llc::AES_LEVEL_256, verify), "Failed to inflate part: %u.", iPart);
				ree_if(verify != partBytes, "Sanity check failed: %s.", "??");
				encrypted.clear();
			}
		}
		else {
			llc_necall(deflated.append((char*)&partBytes.size(), sizeof(uint32_t)), "%s", "Out of memory?");;
			llc_necall(::llc::arrayDeflate(partBytes, deflated), "Failed to deflate part: %u.", iPart);
			if(0 == params.EncryptionKey.size()) {
				info_printf("Saving part file to disk: '%s'. Size: %u.", pathToWriteTo.begin(), deflated.size());
				llc_necall(::llc::fileFromMemory({pathToWriteTo.begin(), pathToWriteTo.size()}, deflated), "Failed to write part: %u.", iPart);
				verify.clear();
				llc_necall(::llc::arrayInflate({&deflated[sizeof(uint32_t)], deflated.size() - sizeof(uint32_t)}, verify), "Failed to inflate part: %u.", iPart);
				ree_if(verify != partBytes, "Sanity check failed: %s.", "??");
				deflated.clear();
			} else {
				llc_necall(::llc::aesEncode(::llc::view_const_byte{deflated.begin(), deflated.size()}, params.EncryptionKey, ::llc::AES_LEVEL_256, encrypted), "Failed to encrypt part: %u.", iPart);
				info_printf("Saving part file to disk: '%s'. Size: %u.", pathToWriteTo.begin(), encrypted.size());
				llc_necall(::llc::fileFromMemory({pathToWriteTo.begin(), pathToWriteTo.size()}, encrypted), "Failed to write part: %u.", iPart);
				deflated.clear();
				llc_necall(::llc::aesDecode(encrypted, params.EncryptionKey, ::llc::AES_LEVEL_256, deflated), "Failed to inflate part: %u.", iPart);
				verify.clear();
				llc_necall(::llc::arrayInflate({&deflated[sizeof(uint32_t)], deflated.size() - sizeof(uint32_t)}, verify), "Failed to inflate part: %u.", iPart);
				ree_if(verify != partBytes, "Sanity check failed: %s.", "??");
				encrypted.clear();
				deflated.clear();
			}
		}
		verify.clear();
	}
	return 0; 
}
