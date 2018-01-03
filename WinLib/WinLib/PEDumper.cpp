#include "PEDumper.h"

using WinLib::PE::PEDumper;

PEDumper::PEDumper() { this->original = NULL; }

PEDumper::PEDumper(PEFile *dumper, std::string name) {
	this->original = original;
	this->name = name;
}

PEDumper::PEDumper(const std::string& path, std::string name) {
	this->original = PEFile::loadFromFile(path);
	this->name = name;
}