#include "ntos.h"

using WinLibKernel::NTOS::NTOS;

//e.g. moduleName="\\SystemRoot\\system32\\ntoskrnl.exe"
PRTL_PROCESS_MODULE_INFORMATION NTOS::GetSystemModuleInformation(char* moduleName)
{
	ULONG returnLength;
	UNICODE_STRING uFunction;
	_ZwQuerySystemInformation pZwQuerySystemInformation;
	PRTL_PROCESS_MODULES prtl_process_modules;
	PRTL_PROCESS_MODULE_INFORMATION module = nullptr;
	NTSTATUS status;

	RtlInitUnicodeString(&uFunction, L"ZwQuerySystemInformation");
	pZwQuerySystemInformation = (_ZwQuerySystemInformation)MmGetSystemRoutineAddress(&uFunction);

	if (!pZwQuerySystemInformation)
		return nullptr;

	status = pZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemModuleInformation, NULL, 0, &returnLength);

	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		prtl_process_modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, returnLength, 'winl');

		if (prtl_process_modules) {
			status = pZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemModuleInformation, (PVOID)prtl_process_modules, returnLength, NULL);

			for (ULONG i = 0; i < prtl_process_modules->NumberOfModules; i++) {
				auto currentModule = prtl_process_modules->Modules[i];

				if (strcmp(currentModule.FullPathName, moduleName) == 0)
				{
					module = (PRTL_PROCESS_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, sizeof(RTL_PROCESS_MODULE_INFORMATION), 'winl');
					RtlCopyMemory(module, &currentModule, sizeof(RTL_PROCESS_MODULE_INFORMATION));
				}
			}

			ExFreePool(prtl_process_modules);
		}
	}

	return module;
}

PUNICODE_STRING NTOS::GetProcessName(HANDLE pid) {
	ULONG returnLength = 0;
	UNICODE_STRING uFunction;
	_ZwQueryInformationProcess pZwQueryInformationProcess = nullptr;
	NTSTATUS status;
	PUNICODE_STRING name = NULL;
	PEPROCESS pEProcess;
	HANDLE processHandle;

	status = PsLookupProcessByProcessId(pid, &pEProcess);

	if (!NT_SUCCESS(status) || !pEProcess) {
		return nullptr;
	}

	status = ObOpenObjectByPointer(pEProcess, 0, NULL, 0, NULL, KernelMode, &processHandle);

	if (!NT_SUCCESS(status) || !pEProcess) {
		return nullptr;
	}

	RtlInitUnicodeString(&uFunction, L"ZwQueryInformationProcess");
	pZwQueryInformationProcess = (_ZwQueryInformationProcess)MmGetSystemRoutineAddress(&uFunction);

	if (!pZwQueryInformationProcess)
		return nullptr;

	status = pZwQueryInformationProcess(processHandle, PROCESSINFOCLASS::ProcessImageFileName, NULL, 0, &returnLength);

	name = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, returnLength, 'winl');

	if (name) {
		status = pZwQueryInformationProcess(processHandle, PROCESSINFOCLASS::ProcessImageFileName, (PVOID)name, returnLength, 0);
	}

	return name;
}

NTSTATUS NTOS::ReadProcessMemoryUserMode(PEPROCESS process, PVOID sourceAddr, PVOID targetAdd, SIZE_T size) {
	UNICODE_STRING uFunction;
	SIZE_T resultSize;
	_MmCopyVirtualMemory pMmCopyVirtualMemory = nullptr;

	RtlInitUnicodeString(&uFunction, L"MmCopyVirtualMemory");
	pMmCopyVirtualMemory = (_MmCopyVirtualMemory)MmGetSystemRoutineAddress(&uFunction);
	PEPROCESS sourceProcess = process;
	PEPROCESS targetProcess = PsGetCurrentProcess();

	return pMmCopyVirtualMemory(sourceProcess, sourceAddr, targetProcess, targetAdd, size, KernelMode, &resultSize);
}

NTSTATUS NTOS::WriteProcessMemoryUserMode(PEPROCESS process, PVOID sourceAddr, PVOID targetAdd, SIZE_T size) {
	UNICODE_STRING uFunction;
	SIZE_T resultSize;
	NTSTATUS status;
	_MmCopyVirtualMemory pMmCopyVirtualMemory = nullptr;

	RtlInitUnicodeString(&uFunction, L"MmCopyVirtualMemory");
	pMmCopyVirtualMemory = (_MmCopyVirtualMemory)MmGetSystemRoutineAddress(&uFunction);
	PEPROCESS sourceProcess = PsGetCurrentProcess();
	PEPROCESS targetProcess = process;

	//Disable MemoryProtection
	PMDL mdl = IoAllocateMdl(targetAdd, (ULONG)size, FALSE, FALSE, NULL);

	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

#pragma warning(push)
#pragma warning(disable: 4995)
		targetAdd = MmGetSystemAddressForMdl(mdl);
#pragma warning(pop)

		MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);

		status = pMmCopyVirtualMemory(sourceProcess, sourceAddr, targetProcess, targetAdd, size, KernelMode, &resultSize);

		MmUnmapLockedPages(targetAdd, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_ACCESS_DENIED;
	}

	return status;
}