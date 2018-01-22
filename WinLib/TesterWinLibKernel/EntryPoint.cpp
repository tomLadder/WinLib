#include <ntddk.h>
#include <cr0.h>
#include <Detour.h>
#include <ntos.h>

using WinLibKernel::Mem::cr0;
using WinLibKernel::Mem::Hook::Detour;
using WinLibKernel::NTOS::NTOS;

Detour* detour;

typedef ULONG(__cdecl *dbgprint)(_In_z_ _Printf_format_string_ PCSTR Format, ...);
dbgprint pDbgPrint;

ULONG __cdecl MyDbgPrint(_In_z_ _Printf_format_string_ PCSTR Format, ...) {
	UNREFERENCED_PARAMETER(Format);
	return pDbgPrint("=> hooked from Kernel");
}

VOID KernelMemManipulation() {
	PCHAR addr;
	UNICODE_STRING apiname;

	RtlInitUnicodeString(&apiname, L"DbgPrint");
	addr = (PCHAR)MmGetSystemRoutineAddress(&apiname);

	detour = new (NonPagedPool) Detour((UINT8*)addr, (UINT8*)&MyDbgPrint);
	detour->hook();
	pDbgPrint = (dbgprint)detour->getTrampoline();
}

VOID GetModuleInformation() {
	auto module_info = NTOS::GetSystemModuleInformation("\\SystemRoot\\system32\\ntoskrnl.exe");

	if (module_info) {
		delete module_info;
	}
}

typedef NTSTATUS(*DriverEntry)(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

NTSTATUS HookedDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

	return STATUS_SUCCESS;
}

VOID HijackIOCTL() {
	//detour = new (NonPagedPool) Detour((UINT8*)addr, (UINT8*)&MyDbgPrint);
	//detour->hook();
}

VOID OnUnload(IN PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	DbgPrint("=> OnUnload called");
}

void NotifyRoutine(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo) {
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ImageInfo);
	UNICODE_STRING uPath;
	WCHAR path[] = L"\\??\\C:\\Users\\Thomas\\Desktop\\dokan2.sys";
	RtlInitUnicodeString(&uPath, path);

	PRINT("=> %wZ", FullImageName);

	//if (RtlCompareUnicodeString(FullImageName, &uPath, TRUE) == FALSE) {
	//	PRINT("=> dokan2.sys loaded");

	//	auto peFile = new (NonPagedPool) PEFile((PCHAR)ImageInfo->ImageBase, (int)ImageInfo->ImageSize);
	//	auto entryPoint = (CHAR*)ImageInfo->ImageBase + peFile->getNtHeader()->OptionalHeader.AddressOfEntryPoint;

	//	detour = new (NonPagedPool) Detour((UINT8*)entryPoint, (UINT8*)&DokanEntry);
	//	detour->hook();
	//}
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	DbgPrint("=> DriverEntry called");
	PsSetLoadImageNotifyRoutine(&NotifyRoutine);
	//DriverObject->DriverUnload = OnUnload;

	//KernelMemManipulation();
	//GetModuleInformation();
	//HijackIOCTL();

	return STATUS_SUCCESS;
}