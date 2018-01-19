#pragma once
#include <ntddk.h>
#include "winstructs.h"
#include "Debug.h"

typedef NTSTATUS(NTAPI *_ZwQuerySystemInformation)
(
	_In_ SYSTEM_INFORMATION_CLASS	SystemInformationClass,
	_Inout_ PVOID					SystemInformation,
	_In_ ULONG						SystemInformationLength,
	_Out_opt_ PULONG				ReturnLength
);

namespace WinLibKernel {
	namespace NTOS {
		class NTOS {
		public:
			static PRTL_PROCESS_MODULE_INFORMATION GetSystemModuleInformation(char* moduleName);
		};
	}
}