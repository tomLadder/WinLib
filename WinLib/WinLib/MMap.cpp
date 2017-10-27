#include "MMap.h"


using WinLib::PE::Loader::MMapper;
using WinLib::PE::PEFile;

int Stub();
void LoaderStub(LPVOID addr);

MMapper::MMapper(PEFile* peFile) {
	this->peFile = peFile;
}

bool MMapper::map(HANDLE handle) {
	return this->mapInternal(handle);
}

bool MMapper::map(DWORD pid) {

	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, true, pid);

	if (!processHandle) {
		std::cout << "OpenProcess failed: " << GetLastError() << std::endl;
		return false;
	}

	auto retValue = this->mapInternal(processHandle);
	CloseHandle(processHandle);

	return retValue;
}

bool MMapper::mapInternal(HANDLE processHandle) {
	if (!this->peFile->isValid()) {
		std::cout << "Error: PEFile not valid" << std::endl;
		return false;
	}

	LPVOID memory = VirtualAllocEx(processHandle, 0, this->peFile->getImageSize(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!memory) {
		std::cout << "VirtualAlloc failed: " << GetLastError() << std::endl;
		CloseHandle(processHandle);
		return false;
	}

	this->payload = new byte[this->peFile->getImageSize()];
	memset(this->payload, 0, this->peFile->getImageSize());

	std::cout << "AllocBase: 0x" << std::hex << memory << std::endl;
	std::cout << "AllocSize: " << this->peFile->getImageSize() << std::endl;

	MMapper::mapHeader();
	MMapper::mapSections();
	MMapper::baseRelocation();
	MMapper::writeToProcess(processHandle, memory, this->peFile->getImageSize());
	MMapper::setProtectionFlags();

	if (!MMapper::executePayload(processHandle, memory)) {
		std::cout << "executePayload() failed" << std::endl;
		VirtualFree(memory, this->peFile->getImageSize(), MEM_FREE);
		CloseHandle(processHandle);

		return false;
	}

	VirtualFree(memory, this->peFile->getImageSize(), MEM_FREE);

	return true;
}

bool MMapper::mapHeader() {
	memcpy(this->payload, this->peFile->getDosHeader(), this->peFile->getHeaderSize());

	return true;
}

bool MMapper::mapSections() {
	for (int i = 0; i < this->peFile->getNumberOfSections(); i++) {
		PIMAGE_SECTION_HEADER sectionHeader = this->peFile->getSectionHeader(i);
		byte* rawData = this->peFile->getSectionBase(i);

		if (!rawData) {
			std::cout << "Could not get Sectionbase" << std::endl;
			return false;
		}

		memcpy(this->payload + sectionHeader->VirtualAddress, rawData, sectionHeader->SizeOfRawData);
	}

	return true;
}

bool MMapper::executePayload(HANDLE processHandle, LPVOID peBase) {
	int loaderStubSize = 200;

	LPVOID loaderMemory = VirtualAllocEx(processHandle, 0, loaderStubSize + sizeof(LoaderParamsMMap), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!loaderMemory) {
		std::cout << "executePayload() - VirtualAllocEx failed" << std::endl;
		return false;
	}

	if (!WriteProcessMemory(processHandle, (byte*)loaderMemory, &LoaderStub, loaderStubSize, 0)) {
		std::cout << "executePayload() - WriteProcessMemory failed" << std::endl;
		return false;
	}

	this->writeLoaderParamsToProcess(processHandle, (byte*)loaderMemory + loaderStubSize, peBase);

	std::cout << "Dll-EntryPoint: 0x" << std::hex << (DWORD64)peBase + this->peFile->getNtHeader()->OptionalHeader.AddressOfEntryPoint << std::endl;
	std::cout << "Shellcode mapped to 0x" << std::hex << loaderMemory << std::endl;
	std::cout << "press a key to continue";
	getchar();

	HANDLE thread = CreateRemoteThreadEx(processHandle, 0, 0, (LPTHREAD_START_ROUTINE)loaderMemory, (byte*)loaderMemory + loaderStubSize, 0, 0, 0);
	WaitForSingleObject(thread, INFINITE);

	std::cout << "Shellcode executed" << std::endl;

	VirtualFree(loaderMemory, loaderStubSize + sizeof(LoaderParamsMMap), MEM_FREE);

	return true;
}

bool MMapper::writeLoaderParamsToProcess(HANDLE processHandle, LPVOID loaderMemory, LPVOID peBase) {
	LoaderParamsMMap params = {};
	memset(&params, 0, sizeof(LoaderParamsMMap));

	params.mapped_PE = (byte*)peBase;
	params.addr_GetProcAdress = (fGetProcAddress)GetProcAddress(GetModuleHandle("Kernel32.dll"), "GetProcAddress");
	params.addr_LoadLibrary = (fLoadLibrary)GetProcAddress(GetModuleHandle("Kernel32.dll"), "LoadLibraryA");
	params.addr_DllMain = (fDllMain)((DWORD64)peBase + this->peFile->getNtHeader()->OptionalHeader.AddressOfEntryPoint);
	params.imports_VA = this->peFile->getNtHeader()->OptionalHeader.DataDirectory[1].VirtualAddress;


	if (!WriteProcessMemory(processHandle, loaderMemory, &params, sizeof(LoaderParamsMMap), 0)) {
		std::cout << "writeLoaderParamsToProcess() - WriteProcessMemory failed" << std::endl;
		return false;
	}

	return true;
}

bool MMapper::writeToProcess(HANDLE processHandle, LPVOID memBase, int size) {
	if (!WriteProcessMemory(processHandle, memBase, this->payload, size, 0)) {
		std::cout << "writeToProcess() - WriteProcessMemory failed" << std::endl;
		return false;
	}

	return true;
}

bool MMapper::baseRelocation() {
	//fix base relocs
	ULONG count;
	ULONG_PTR address;
	PUSHORT typeOffset;

	auto dir = (PIMAGE_BASE_RELOCATION)((byte*)this->payload + this->peFile->getNtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	auto dirend = dir + dir->SizeOfBlock;

	while (dir < dirend && dir->SizeOfBlock > 0) {
		count = dir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / sizeof(USHORT);
		//address = (ULONG_PTR)RVA(this->payload, dir->VirtualAddress);

		//RVA(0, 0);

		typeOffset = (PUSHORT)(dir + 1);
	}

	return true;
}

bool MMapper::setProtectionFlags() {
	return true;
}

int Stub() {
	return 0;
}

void LoaderStub(LPVOID ldrParams) {
	auto loaderParams = (LoaderParamsMMap*)(ldrParams);
	auto import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((byte*)loaderParams->mapped_PE + loaderParams->imports_VA);

	while ((import_descriptor->OriginalFirstThunk != 0 || import_descriptor->OriginalFirstThunk != 0)) {
		char* name = (char*)loaderParams->mapped_PE + import_descriptor->Name;

		HMODULE module = loaderParams->addr_LoadLibrary(name);

		if (import_descriptor->OriginalFirstThunk != 0) {
			PIMAGE_THUNK_DATA64 image_thunk_data = (PIMAGE_THUNK_DATA64)((byte*)loaderParams->mapped_PE + import_descriptor->OriginalFirstThunk);
			PIMAGE_THUNK_DATA64 first_thunk_data = (PIMAGE_THUNK_DATA64)((byte*)loaderParams->mapped_PE + import_descriptor->FirstThunk);
			while (image_thunk_data->u1.AddressOfData != 0) {
				PIMAGE_IMPORT_BY_NAME image_import_by_name = (PIMAGE_IMPORT_BY_NAME)((byte*)loaderParams->mapped_PE + image_thunk_data->u1.Ordinal);
				FARPROC func = loaderParams->addr_GetProcAdress(module, image_import_by_name->Name);
				first_thunk_data->u1.Function = (ULONGLONG)func;

				first_thunk_data++;
				image_thunk_data++;
			}
		}

		import_descriptor++;
	}

	loaderParams->addr_DllMain((HINSTANCE)loaderParams->mapped_PE, DLL_PROCESS_ATTACH, 0);

	return;
}