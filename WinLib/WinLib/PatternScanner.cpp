#include "PatternScanner.h"

using WinLib::Mem::PatternScanner;
using WinLib::PE::PEFile;

uint8_t* PatternScanner::search_internal(byte* start, int size, const char* pattern, const char* mask) {
	auto len = strlen(mask);

	for (auto i = 0; i < size; i++) {
		bool found = true;

		for (int j = 0; j < len; j++) {
			if (mask[j] == '?')
				continue;

			if (((unsigned int)(unsigned char)pattern[j]) != start[i + j]) {
				found = false;
				break;
			}
		}

		if (found) {
			return &start[i];
		}
	}

	return nullptr;
}

uint8_t* PatternScanner::search(std::string moduleName) {
	return nullptr;
}

uint8_t* PatternScanner::search(const char* pattern, const char* mask) {
	auto pe = PEFile::PEFile();

	auto start = pe.getCodeBase();
	auto size = pe.getCodeSize();

	return PatternScanner::search_internal(start, size, pattern, mask);
}