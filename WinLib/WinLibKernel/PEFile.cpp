#include "PEFile.h"

using WinLibKernel::PE::PEFile;

PEFile::PEFile() {
	this->rawData = nullptr;
	this->rawDataSize = 0;
	this->isInMemory = true;
}

PEFile::PEFile(char* rawData, int rawDataSize) {
	this->rawData = rawData;
	this->rawDataSize = rawDataSize;
	this->isInMemory = false;

	this->dosHeader = (PIMAGE_DOS_HEADER)this->rawData;
	this->ntHeader = (PIMAGE_NT_HEADERS)(this->rawData + this->dosHeader->e_lfanew);
	this->sectionHeader = (PIMAGE_SECTION_HEADER)((CHAR*)this->ntHeader + sizeof(IMAGE_NT_HEADERS));
	this->sectionBase = (CHAR*)this->sectionHeader + (sizeof(IMAGE_SECTION_HEADER) * this->getNumberOfSections());
}

void PEFile::printInfos() {
	PRINT("=> EntryPoint:            0x%x", this->ntHeader->OptionalHeader.AddressOfEntryPoint);
	PRINT("=> ImageBase:             0x%x", this->ntHeader->OptionalHeader.ImageBase);
	PRINT("=> SizeOfImage:           0x%x", this->ntHeader->OptionalHeader.SizeOfImage);
	PRINT("=> BaseOfCode:            0x%x", this->ntHeader->OptionalHeader.BaseOfCode);
	PRINT("=> DllCharacteristics:    0x%x", this->ntHeader->OptionalHeader.DllCharacteristics);
	PRINT("=> SizeOfHeader:          0x%x", this->ntHeader->OptionalHeader.SizeOfHeaders);
}

void PEFile::printSections() {
	for (int i = 0; i < this->getNumberOfSections(); i++) {
		IMAGE_SECTION_HEADER section = this->sectionHeader[i];
		PRINT("=> (%d) %s", i, section.Name);
		PRINT("=>      #SizeOfRawData:         %x", section.SizeOfRawData);
		PRINT("=>      #VirtualAdress:         %x", section.VirtualAddress);
		PRINT("=>      #NumberOfRelocations:   %x", section.NumberOfRelocations);
		PRINT("=>      #Characteristics:       %x", section.Characteristics);
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

CHAR* PEFile::getSectionBase(int num) {
	auto section = PEFile::getSectionHeader(num);

	if (!section)
		return nullptr;

	return (CHAR*)this->dosHeader + section->PointerToRawData;
}

CHAR* PEFile::getCodeBase() {
	return (CHAR*)this->dosHeader + this->ntHeader->OptionalHeader.BaseOfCode;
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
	return (PIMAGE_BASE_RELOCATION)((CHAR*)this->ntHeader + sizeof(this->ntHeader->Signature) + sizeof(this->ntHeader->OptionalHeader) + this->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
}

PIMAGE_IMPORT_DESCRIPTOR PEFile::getImportDescriptor() {
	return (PIMAGE_IMPORT_DESCRIPTOR)((DWORD64)this->ntHeader + sizeof(this->ntHeader) + (DWORD64)this->ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
}

/* static */

//e.g. path=\\DosDevices\\C:\\WINDOWS\\example.txt
PEFile* PEFile::loadFromFile(PWCHAR path) {
	HANDLE fileHandle;
	ACCESS_MASK desiredAccess = GENERIC_READ;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK   ioStatusBlock;
	ULONG fileAttributes = FILE_ATTRIBUTE_NORMAL;
	ULONG createDisposition = FILE_OPEN;
	ULONG createOptions = FILE_SYNCHRONOUS_IO_ALERT;
	UNICODE_STRING uniPath;
	NTSTATUS ntstatus;
	IO_STATUS_BLOCK io_status_block = { 0 };
	FILE_STANDARD_INFORMATION fileInformation = { 0 };
	PVOID fileData;

	RtlInitUnicodeString(&uniPath, path);
	InitializeObjectAttributes(&objectAttributes, &uniPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return nullptr;

	ntstatus = ZwCreateFile(&fileHandle,
							desiredAccess, 
							&objectAttributes, 
							&ioStatusBlock,
							NULL, 
							fileAttributes, 0, 
							createDisposition, 
							createOptions, 
							NULL, 0);

	if (!NT_SUCCESS(ntstatus))
		return nullptr;

	ntstatus = ZwQueryInformationFile(fileHandle, &io_status_block, &fileInformation, sizeof(fileInformation), FileStandardInformation);

	if (!NT_SUCCESS(ntstatus)) {
		ZwClose(fileHandle);
		return nullptr;
	}

	//Attention: the allocated memory has to be somewhere delted
	fileData = ExAllocatePoolWithTag(PagedPool, fileInformation.EndOfFile.QuadPart, 'mmap');

	ntstatus = ZwReadFile(fileHandle, NULL, NULL, NULL, &io_status_block, fileData, fileInformation.EndOfFile.LowPart, NULL, NULL);

	if (!NT_SUCCESS(ntstatus)) {
		ZwClose(fileHandle);
		return nullptr;
	}

	ZwClose(fileHandle);

	return new (NonPagedPool) PEFile(reinterpret_cast<PCHAR>(fileData), fileInformation.EndOfFile.LowPart);
}