#include "MMapDll.h"

#define RVA(m, b) ((PVOID)((ULONG_PTR)(b)+(ULONG_PTR)(m)))

using WinLibKernel::PE::Loader::MMapperDll;
using WinLibKernel::PE::PEFile;
using WinLibKernel::NTOS::NTOS;

MMapperDll::MMapperDll(PEFile *peFile) {
	this->peFile = peFile;
}

MMapperDll::STATUS MMapperDll::map(PEPROCESS process, PVOID originalEntryPoint, PVOID targetBase, DWORD64 targetSize) {
	if (!this->peFile->isValid()) {
		return PEINVALID;
	}

	this->payload = ExAllocatePoolWithTag(NonPagedPool, this->peFile->getImageSize(), 'winl');
	memset(this->payload, 0, this->peFile->getImageSize());

	if (!MMapperDll::mapHeader())
		return STATUS::FAILED;

	if (!MMapperDll::mapSections())
		return STATUS::FAILED;

	if (!MMapperDll::fixImports())
		return STATUS::FAILED;

	if (!MMapperDll::baseRelocation(targetBase))
		return STATUS::FAILED;

	if (!MMapperDll::writeToProcess(process, targetBase, targetSize))
		return STATUS::FAILED;

	if (!MMapperDll::patchEntryPoint(originalEntryPoint))
		return STATUS::FAILED;

	NTSTATUS status;
	unsigned char patch = 0xC3;
	status = NTOS::NTOS::WriteProcessMemoryUserMode(process, &patch, originalEntryPoint, sizeof(unsigned char));
	if (!NT_SUCCESS(status)) {
		PRINT("=> NTOS::WriteProcessMemory failed: 0x%x", status);
	}

	ExFreePool(this->payload);

	return MMapperDll::STATUS::SUCCESS;
}

bool MMapperDll::mapHeader() {
	RtlCopyMemory(this->payload, this->peFile->getDosHeader(), this->peFile->getHeaderSize());

	return true;
}

bool MMapperDll::mapSections() {
	for (int i = 0; i < this->peFile->getNumberOfSections(); i++) {
		PIMAGE_SECTION_HEADER sectionHeader = this->peFile->getSectionHeader(i);
		CHAR* rawData = this->peFile->getSectionBase(i);

		if (!rawData) {
			return false;
		}

		RtlCopyMemory((CHAR*)this->payload + sectionHeader->VirtualAddress, rawData, sectionHeader->SizeOfRawData);
	}

	return true;
}


bool MMapperDll::baseRelocation(PVOID targetBase) {
	ULONG count;
	ULONG_PTR address;
	PUSHORT typeOffset;
	LONGLONG delta;

	delta = (ULONG_PTR)targetBase - this->peFile->getNtHeader()->OptionalHeader.ImageBase;
	auto dir = (PIMAGE_BASE_RELOCATION)((CHAR*)this->payload + this->peFile->getNtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	auto dirend = dir + this->peFile->getNtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	while (dir < dirend && dir->SizeOfBlock > 0) {
		count = (dir->SizeOfBlock - 8) >> 1;
		address = (ULONG_PTR)RVA(payload, dir->VirtualAddress);
		typeOffset = (PUSHORT)(dir + 1);
		this->processRelocation(address, count, typeOffset, delta);

		dir = dir + dir->SizeOfBlock;
	}

	return true;
}

PIMAGE_BASE_RELOCATION MMapperDll::processRelocation(ULONG_PTR address, ULONG count, PUSHORT typeOffset, LONGLONG delta) {
	SHORT offset;
	USHORT type;
	PUSHORT shortPtr;
	PULONG longPtr;
	PULONGLONG longLongPtr;

	for (ULONG i = 0; i < count; i++) {
		offset = *typeOffset & 0xFFF;
		type = *typeOffset >> 12;
		shortPtr = (PUSHORT)(RVA(address, offset));

		switch (type) {
		case IMAGE_REL_BASED_DIR64:
			longLongPtr = (PUINT64)RVA(address, offset);
			*longLongPtr = *longLongPtr + delta;
			break;
		case IMAGE_REL_BASED_HIGHLOW:
			longPtr = (PULONG)RVA(address, offset);
			*longPtr = *longPtr + (delta & 0xFFFFFFFF);
			break;
		default:
			return (PIMAGE_BASE_RELOCATION)NULL;
		}

		typeOffset++;
	}

	return (PIMAGE_BASE_RELOCATION)typeOffset;
}

bool MMapperDll::fixImports() {
	return true;
}

bool MMapperDll::writeToProcess(PEPROCESS process, PVOID targetBase, DWORD64 targetSize) {
	NTSTATUS status;

	status = NTOS::NTOS::WriteProcessMemoryUserMode(process, this->payload, targetBase, targetSize);

	PRINT("=> status: 0x%X", status);

	return status == STATUS_SUCCESS;
}

bool MMapperDll::patchEntryPoint(PVOID originalEntryPoint) {
	UNREFERENCED_PARAMETER(originalEntryPoint);

	return true;
}