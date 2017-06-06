#pragma once
#include <Windows.h>
#include "HandleInformation.h"
#include "WinProcess.h"

using WinLib::HandleInformation;

#define NT_SUCCESS(x) ((x) >= 0)

#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

namespace WinLib {
	class WinHandle {
	private:
		typedef NTSTATUS(*NtQuerySystemInformation)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
		NtQuerySystemInformation pNtQuerySystemInformation;

		static WinHandle* _instance;
		WinHandle();
	public:
		static WinHandle* getInstance();

		std::vector<std::shared_ptr<HandleInformation>> getHandle(DWORD pid, DWORD access_mask, bool ownOnly);
	};
};