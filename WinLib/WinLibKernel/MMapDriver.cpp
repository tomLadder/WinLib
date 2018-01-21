#include "MMapDriver.h"

#define RVA(m, b) ((PVOID)((ULONG_PTR)(b)+(ULONG_PTR)(m)))

NTSTATUS(*DriverEntry)(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

using WinLibKernel::PE::Loader::MMapperDriver;
using WinLibKernel::PE::PEFile;

MMapperDriver::MMapperDriver(PEFile* peFile) {
	this->peFile = peFile;
	this->driver_object = nullptr;
}

MMapperDriver::MMapperDriver(PEFile *peFile, PDRIVER_OBJECT driver_object) {
	this->peFile = peFile;
	this->driver_object = driver_object;
}

MMapperDriver::STATUS MMapperDriver::map() {
	HANDLE threadHandle = NULL;
	CLIENT_ID clientID = { 0 };
	OBJECT_ATTRIBUTES obAttr = { 0 };
	PVOID pThread = NULL;
	OBJECT_HANDLE_INFORMATION handleInfo = { 0 };

	union compilerHack {
		WinLibKernel::PE::Loader::MMapperDriver::STATUS(*func)(WinLibKernel::PE::Loader::MMapperDriver* this_ptr);
		PVOID addr;
	};

	compilerHack chack = { &MMapperDriver::mapInternal };

	InitializeObjectAttributes(&obAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	auto status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, &obAttr, NULL, &clientID, (PKSTART_ROUTINE)chack.addr, this);

	if (!NT_SUCCESS(status)) {
		return STATUS::FAILED;
	}

	status = ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &pThread, &handleInfo);

	if (NT_SUCCESS(status)) {
		KeWaitForSingleObject(pThread, Executive, KernelMode, TRUE, NULL);
		//Catch ExitCode
	}

	if (pThread) {
		ObDereferenceObject(pThread);
	}

	return STATUS::SUCCESS;
}

MMapperDriver::STATUS MMapperDriver::mapInternal(MMapperDriver* this_ptr) {

	if (!this_ptr->peFile->isValid()) {
		return PEINVALID;
	}

#pragma region Alloc Kernel space
	PHYSICAL_ADDRESS start = { 0 };
	PHYSICAL_ADDRESS end = { 0 };
	end.QuadPart = MAXULONG64;

	auto mdl = MmAllocatePagesForMdl(start, end, start, this_ptr->peFile->getImageSize());

	if (!mdl) {
		return FAILED;
	}

	this_ptr->mapBase = MmGetSystemAddressForMdl(mdl);

	if (!this_ptr->mapBase) {
		MmFreePagesFromMdl(mdl);
		return FAILED;
	}
#pragma endregion


	PRINT("=> AllocBase: 0x%x", this_ptr->mapBase);
	PRINT("=> AllocSize: %d", this_ptr->peFile->getImageSize());

	this_ptr->mapHeader();
	this_ptr->mapSections();
	this_ptr->baseRelocation(this_ptr->mapBase);
	this_ptr->fixImports();
	this_ptr->executeMappedMemory();

	MmFreePagesFromMdl(mdl);
	PsTerminateSystemThread(STATUS_SUCCESS);

	return SUCCESS;
}

bool MMapperDriver::mapHeader() {
	RtlCopyMemory(this->mapBase, this->peFile->getDosHeader(), this->peFile->getHeaderSize());

	return true;
}

bool MMapperDriver::mapSections() {
	for (int i = 0; i < this->peFile->getNumberOfSections(); i++) {
		auto sectionHeader = this->peFile->getSectionHeader(i);
		auto rawData = this->peFile->getSectionBase(i);

		if (!rawData) {
			PRINT("=> Could not get Sectionbase");
			return false;
		}

		RtlCopyMemory((PVOID)((CHAR*)this->mapBase + sectionHeader->VirtualAddress), (PVOID)rawData, (int)sectionHeader->SizeOfRawData);
	}

	return true;
}

bool MMapperDriver::baseRelocation(PVOID targetBase) {
	ULONG count;
	ULONG_PTR address;
	PUSHORT typeOffset;
	LONGLONG delta;

	delta = (ULONG_PTR)targetBase - this->peFile->getNtHeader()->OptionalHeader.ImageBase;
	auto dir = (PIMAGE_BASE_RELOCATION)((CHAR*)this->mapBase + this->peFile->getNtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	auto dirend = dir + this->peFile->getNtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	while (dir < dirend && dir->SizeOfBlock > 0) {
		count = (dir->SizeOfBlock - 8) >> 1;
		address = (ULONG_PTR)RVA((CHAR*)this->mapBase, dir->VirtualAddress);
		typeOffset = (PUSHORT)(dir + 1);
		this->processRelocation(address, count, typeOffset, delta);

		dir = dir + dir->SizeOfBlock;
	}

	return true;
}

PIMAGE_BASE_RELOCATION MMapperDriver::processRelocation(ULONG_PTR address, ULONG count, PUSHORT typeOffset, LONGLONG delta) {
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
			PRINT("=> Unknown fixup type: 0x%x", type);
			return (PIMAGE_BASE_RELOCATION)NULL;
		}

		typeOffset++;
	}

	return (PIMAGE_BASE_RELOCATION)typeOffset;
}

bool MMapperDriver::fixImports() {
	auto import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((CHAR*)this->mapBase + this->peFile->getNtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	
	while ((import_descriptor->OriginalFirstThunk != 0 || import_descriptor->OriginalFirstThunk != 0)) {
		if (import_descriptor->OriginalFirstThunk != 0) {
			PIMAGE_THUNK_DATA64 image_thunk_data = (PIMAGE_THUNK_DATA64)((CHAR*)this->mapBase + import_descriptor->OriginalFirstThunk);
			PIMAGE_THUNK_DATA64 first_thunk_data = (PIMAGE_THUNK_DATA64)((CHAR*)this->mapBase + import_descriptor->FirstThunk);
			while (image_thunk_data->u1.AddressOfData != 0) {
				PIMAGE_IMPORT_BY_NAME image_import_by_name = (PIMAGE_IMPORT_BY_NAME)((CHAR*)this->mapBase + image_thunk_data->u1.Ordinal);

				UNICODE_STRING func_name;
				WCHAR wfunc_name[1024];
				mbstowcs(wfunc_name, image_import_by_name->Name, strlen(image_import_by_name->Name) + 1);

				RtlInitUnicodeString(&func_name, wfunc_name);
				auto func = MmGetSystemRoutineAddress(&func_name);
				first_thunk_data->u1.Function = (ULONGLONG)func;

				first_thunk_data++;
				image_thunk_data++;
			}
		}

		import_descriptor++;
	}

	return true;
}

bool MMapperDriver::executeMappedMemory() {
	auto entryPoint = (CHAR*)this->mapBase + this->peFile->getNtHeader()->OptionalHeader.AddressOfEntryPoint;

	*(CHAR **)&DriverEntry = entryPoint;
	if (this->driver_object)
		DriverEntry(this->driver_object, NULL);
	else
		DriverEntry(NULL, NULL);

	return true;
}