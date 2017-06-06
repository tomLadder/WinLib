#include "PEFile.h"

using WinLib::PE::PEFile;

PEFile::PEFile() {
	this->rawData = nullptr;
	this->rawDataSize = 0;
	this->isInMemory = true;

	auto base = reinterpret_cast<uint8_t*>(GetModuleHandle(NULL));

	if (base) {
		this->dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		this->ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(base + this->dosHeader->e_lfanew);
		this->sectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>((BYTE*)this->ntHeader + sizeof(IMAGE_NT_HEADERS));
		this->sectionBase = (byte*)this->sectionHeader + (sizeof(IMAGE_SECTION_HEADER) * this->getNumberOfSections());
	}
}

PEFile::PEFile(const std::string& moduleName) {
	this->rawData = nullptr;
	this->rawDataSize = 0;
	this->isInMemory = true;

	auto base = reinterpret_cast<uint8_t*>(GetModuleHandle(moduleName.c_str()));

	if (base) {
		this->dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		this->ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(base + this->dosHeader->e_lfanew);
		this->sectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>((BYTE*)this->ntHeader + sizeof(IMAGE_NT_HEADERS));
		this->sectionBase = (byte*)this->sectionHeader + (sizeof(IMAGE_SECTION_HEADER) * this->getNumberOfSections());
	}
}

PEFile::PEFile(char* rawData, int rawDataSize) {
	this->rawData = rawData;
	this->rawDataSize = rawDataSize;
	this->isInMemory = false;

	this->dosHeader = (PIMAGE_DOS_HEADER)this->rawData;
	this->ntHeader = (PIMAGE_NT_HEADERS)(this->rawData + this->dosHeader->e_lfanew);
	this->sectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)this->ntHeader + sizeof(IMAGE_NT_HEADERS));
	this->sectionBase = (byte*)this->sectionHeader + (sizeof(IMAGE_SECTION_HEADER) * this->getNumberOfSections());
}

void PEFile::printInfos() {
	std::cout << "EntryPoint:            0x" << std::hex << this->ntHeader->OptionalHeader.AddressOfEntryPoint << std::endl;
	std::cout << "ImageBase:             0x" << std::hex << this->ntHeader->OptionalHeader.ImageBase << std::endl;
	std::cout << "SizeOfImage:           0x" << std::hex << this->ntHeader->OptionalHeader.SizeOfImage << std::endl;
	std::cout << "BaseOfCode:            0x" << std::hex << this->ntHeader->OptionalHeader.BaseOfCode << std::endl;
	std::cout << "DllCharacteristics:    0x" << std::hex << this->ntHeader->OptionalHeader.DllCharacteristics << std::endl;
	std::cout << "SizeOfHeader:          0x" << std::hex << this->ntHeader->OptionalHeader.SizeOfHeaders << std::endl;
}

void PEFile::printSections() {
	for (int i = 0; i < this->getNumberOfSections(); i++) {
		IMAGE_SECTION_HEADER section = this->sectionHeader[i];
		std::cout << "(" << i << ")" << " " << section.Name << std::endl;
		std::cout << "     #SizeOfRawData:         " << std::hex << section.SizeOfRawData << std::endl;
		std::cout << "     #VirtualAdress:         " << std::hex << section.VirtualAddress << std::endl;
		std::cout << "     #NumberOfRelocations:   " << std::hex << section.NumberOfRelocations << std::endl;
		std::cout << "     #Characteristics:       " << std::hex << section.Characteristics << std::endl << std::endl;
	}
}

bool PEFile::isValid() {
	return this->dosHeader->e_magic == IMAGE_DOS_SIGNATURE;
}

int PEFile::getNumberOfSections() {
	return this->ntHeader->FileHeader.NumberOfSections;
}

int PEFile::getRawDataSize() {
	return this->rawDataSize;
}

char* PEFile::getRawData() {
	return this->rawData;
}

int PEFile::getImageSize() {
	return this->ntHeader->OptionalHeader.SizeOfImage;
}

int PEFile::getHeaderSize() {
	return this->ntHeader->OptionalHeader.SizeOfHeaders;
}

PIMAGE_SECTION_HEADER PEFile::getSectionHeader(int num) {
	if (num > this->getNumberOfSections())
		return nullptr;

	return &this->sectionHeader[num];
}

byte* PEFile::getSectionBase(int num) {
	PIMAGE_SECTION_HEADER sectionHeader = PEFile::getSectionHeader(num);

	if (!sectionHeader)
		return nullptr;

	return (byte*)this->dosHeader + sectionHeader->PointerToRawData;
}

byte* PEFile::getCodeBase() {
	return (byte*)this->dosHeader + this->ntHeader->OptionalHeader.BaseOfCode;
}

int PEFile::getCodeSize() {
	return this->ntHeader->OptionalHeader.SizeOfCode;
}

PIMAGE_NT_HEADERS PEFile::getNtHeader() {
	return this->ntHeader;
}

PIMAGE_DOS_HEADER PEFile::getDosHeader() {
	return this->dosHeader;
}

PIMAGE_SECTION_HEADER PEFile::getSectionHeader() {
	return this->sectionHeader;
}

PIMAGE_BASE_RELOCATION PEFile::getBaseRelocation() {
	return (PIMAGE_BASE_RELOCATION)((byte*)this->ntHeader + sizeof(this->ntHeader->Signature) + sizeof(this->ntHeader->OptionalHeader) + this->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
}

PIMAGE_IMPORT_DESCRIPTOR PEFile::getImportDescriptor() {
	return (PIMAGE_IMPORT_DESCRIPTOR)((DWORD64)this->ntHeader + sizeof(this->ntHeader) + (DWORD64)this->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
}