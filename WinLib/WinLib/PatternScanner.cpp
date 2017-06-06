#include "PatternScanner.h"

using WinLib::Mem::PatternScanner;
using WinLib::PE::PEFile;

uint8_t* PatternScanner::search_internal() {
	return nullptr;
}

uint8_t* PatternScanner::search(std::string moduleName) {

}

uint8_t* PatternScanner::search() {
	auto pe = PEFile::PEFile();

	auto start = pe.getCodeBase();
	auto size = pe.getCodeSize();

	return nullptr;
}