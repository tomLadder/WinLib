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
		}

		ExFreePool(prtl_process_modules);
	}

	return module;
}