#include <ntifs.h>
#include <ntddk.h>
#include <cr0.h>
#include <Detour.h>
#include <ntos.h>
#include <PEFile.h>
#include <MMapDriver.h>

using WinLibKernel::Mem::cr0;
using WinLibKernel::Mem::Hook::Detour;
using WinLibKernel::NTOS::NTOS;
using WinLibKernel::PE::PEFile;
using WinLibKernel::PE::Loader::MMapperDriver;

//Detour* detour;
//
//typedef ULONG(__cdecl *dbgprint)(_In_z_ _Printf_format_string_ PCSTR Format, ...);
//dbgprint pDbgPrint;
//
//ULONG __cdecl MyDbgPrint(_In_z_ _Printf_format_string_ PCSTR Format, ...) {
//	UNREFERENCED_PARAMETER(Format);
//	return pDbgPrint("=> hooked from Kernel");
//}
//
//VOID KernelMemManipulation() {
//	PCHAR addr;
//	UNICODE_STRING apiname;
//
//	RtlInitUnicodeString(&apiname, L"DbgPrint");
//	addr = (PCHAR)MmGetSystemRoutineAddress(&apiname);
//
//	detour = new (NonPagedPool) Detour((UINT8*)addr, (UINT8*)&MyDbgPrint);
//	detour->hook();
//	pDbgPrint = (dbgprint)detour->getTrampoline();
//}
//
//VOID GetModuleInformation() {
//	auto module_info = NTOS::GetSystemModuleInformation("\\SystemRoot\\system32\\ntoskrnl.exe");
//
//	if (module_info) {
//		delete module_info;
//	}
//}
//
//typedef NTSTATUS(*_DriverEntry)(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
//_DriverEntry pDriverEntry;
//
//PVOID base;
//DWORD imageSize;
//NTSTATUS HookedDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
//	PRINT("=> HookedDriverEntry");
//
//	auto peFile = PEFile::loadFromFile(L"\\DosDevices\\C:\\Users\\Thomas\\Desktop\\EmptyDriver.sys");
//
//	if (peFile == nullptr) {
//		PRINT("=> PEFile::loadFromFile failed");
//		return STATUS_SUCCESS;
//	}
//
//	peFile->printInfos();
//
//	auto mmap = new (PagedPool) MMapperDriver(peFile, DriverObject);
//
//	PVOID entryPoint = mmap->map(base, imageSize);
//
//	if (entryPoint != NULL)
//		PRINT("=> sys manualmapped");
//	else
//		PRINT("=> manualmapping failed!");
//
//	delete mmap;
//	delete peFile;
//
//	pDriverEntry = (_DriverEntry)(entryPoint);
//	return pDriverEntry(DriverObject, RegistryPath);
//}
//
//VOID HijackIOCTL() {
//	//detour = new (NonPagedPool) Detour((UINT8*)addr, (UINT8*)&MyDbgPrint);
//	//detour->hook();
//}
//
//VOID OnUnload(IN PDRIVER_OBJECT DriverObject) {
//	UNREFERENCED_PARAMETER(DriverObject);
//
//	if (detour) {
//		detour->unhook();
//		delete detour;
//	}
//
//	DbgPrint("=> OnUnload called");
//}
//
//void NotifyRoutine(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo) {
//	UNREFERENCED_PARAMETER(ProcessId);
//	UNREFERENCED_PARAMETER(ImageInfo);
//	UNICODE_STRING uPath;
//	WCHAR path[] = L"\\??\\C:\\Users\\Thomas\\Desktop\\EasyAntiCheat.sys";
//	RtlInitUnicodeString(&uPath, path);
//
//	if (RtlCompareUnicodeString(FullImageName, &uPath, TRUE) == FALSE) {
//		base = ImageInfo->ImageBase;
//		imageSize = (DWORD)ImageInfo->ImageSize;
//
//		auto peFile = new (NonPagedPool) PEFile((PCHAR)ImageInfo->ImageBase, (int)ImageInfo->ImageSize);
//		auto entryPoint = (CHAR*)ImageInfo->ImageBase + peFile->getNtHeader()->OptionalHeader.AddressOfEntryPoint;
//
//		detour = new (NonPagedPool) Detour((UINT8*)entryPoint, (UINT8*)&HookedDriverEntry);
//		detour->hook();
//
//		pDriverEntry = (_DriverEntry)detour->getTrampoline();
//	}
//}

void LoadImageNotifyRoutine(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo) {
	UNREFERENCED_PARAMETER(ImageInfo);
	UNREFERENCED_PARAMETER(FullImageName);
	PUNICODE_STRING notifyPath;
	UNICODE_STRING uPathProcess, uPathDll;
	NTSTATUS status;
	PEPROCESS pEPROCESS = NULL;
	PKAPC_STATE state = NULL;
	//PEFile* peFile = NULL;
	CHAR BUFFER[1024];

	WCHAR wpathProcess[] = L"\\Device\\HarddiskVolume2\\Program Files (x86)\\Microsoft DirectX SDK (June 2010)\\Samples\\C++\\Direct3D11\\Bin\\x64\\EmptyProject11.exe";
	WCHAR wpathDll[] = L"\\Fraps\\fraps64.dll";

	RtlInitUnicodeString(&uPathProcess, wpathProcess);
	RtlInitUnicodeString(&uPathDll, wpathDll);

	if (RtlCompareUnicodeString(FullImageName, &uPathDll, TRUE) == FALSE) {
		notifyPath = NTOS::GetProcessName(ProcessId);
		if (notifyPath) {
			if (RtlCompareUnicodeString(notifyPath, &uPathProcess, TRUE) == FALSE) {
				PRINT("=> found dll to hijack");
				status = PsLookupProcessByProcessId(ProcessId, &pEPROCESS);
				if (NT_SUCCESS(status)) {
					KeStackAttachProcess(pEPROCESS, state);
					RtlCopyMemory(BUFFER, ImageInfo->ImageBase, 100);
				}
			}
		}
	}
}

VOID OnUnload(IN PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	PsRemoveLoadImageNotifyRoutine(&LoadImageNotifyRoutine);

	DbgPrint("=> OnUnload called");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	DbgPrint("=> DriverEntry called");
	PsSetLoadImageNotifyRoutine(&LoadImageNotifyRoutine);
	DriverObject->DriverUnload = OnUnload;

	//KernelMemManipulation();
	//GetModuleInformation();
	//HijackIOCTL();

	return STATUS_SUCCESS;
}