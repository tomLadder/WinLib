#include "PEData.h"

using WinLib::Communication::Raw::PEData;

PEData::PEData(uint8_t* pe, uint64_t size) 
	: RawData(PEData::type, size) 
{
	this->pe = pe;
}

PEData::PEData(PEFile* peFile) 
	: RawData(PEData::type, peFile->getRawDataSize()) 
{
	this->pe = reinterpret_cast<uint8_t*>(peFile->getRawData());
}