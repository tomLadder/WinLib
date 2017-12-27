#include "PEAnalyser.h"

using WinLib::PE::PEAnalyser;
using WinLib::PE::PEFile;

#include "PEAnalyser.h"

PEFile* PEAnalyser::load(std::string path) {
	std::ifstream stream(path, std::ifstream::binary);
	if (stream) {
		stream.seekg(0, stream.end);
		auto length = stream.tellg();
		stream.seekg(0, stream.beg);

		char* rawData = new char[length];
		stream.read(rawData, length);

		if (stream) {
			stream.close();
			return new PEFile(rawData, (int)length);
		}

		delete rawData;
		stream.close();
	}

	return nullptr;
}

PEFile* PEAnalyser::loadFromMemory() {
	return nullptr;
}