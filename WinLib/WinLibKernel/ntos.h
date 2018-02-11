#pragma once
#include <ntifs.h>
#include "winstructs.h"
#include "Debug.h"

typedef NTSTATUS(NTAPI *_ZwQuerySystemInformation)
(
	_In_ SYSTEM_INFORMATION_CLASS	SystemInformationClass,
	_Inout_ PVOID					SystemInformation,
	_In_ ULONG						SystemInformationLength,
	_Out_opt_ PULONG				ReturnLength
);

typedef NTSTATUS(NTAPI *_ZwQueryInformationProcess)
(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);

typedef NTSTATUS(NTAPI *_MmCopyVirtualMemory)
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

namespace WinLibKernel {
	namespace NTOS {
		class NTOS {
		public:
			static PRTL_PROCESS_MODULE_INFORMATION GetSystemModuleInformation(char* moduleName);
			static PUNICODE_STRING GetProcessName(HANDLE pid);
			static NTSTATUS NTOS::ReadProcessMemoryUserMode(PEPROCESS process, PVOID sourceAddr, PVOID targetAdd, SIZE_T size);
			static NTSTATUS NTOS::WriteProcessMemoryUserMode(PEPROCESS process, PVOID sourceAddr, PVOID targetAdd, SIZE_T size);
		};
	}
}