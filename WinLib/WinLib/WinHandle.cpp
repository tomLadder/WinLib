#include "WinHandle.h"

using WinLib::WinHandle;

WinHandle* WinHandle::_instance = nullptr;

WinHandle::WinHandle() {
	this->pNtQuerySystemInformation = (NtQuerySystemInformation)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
}

WinHandle* WinHandle::getInstance() {
	if (WinHandle::_instance == nullptr)
		WinHandle::_instance = new WinHandle();

	return _instance;
}

std::vector<std::shared_ptr<HandleInformation>> WinHandle::getHandle(DWORD pid, DWORD access_mask) {

	std::cout << "PID: " << pid << std::endl;

	std::vector<std::shared_ptr<HandleInformation>> vec;

	PSYSTEM_HANDLE_INFORMATION handleInfos;
	ULONG handleInfoSize = 0x10000;
	NTSTATUS status;

	handleInfos = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

	while ((status = this->pNtQuerySystemInformation(0x10, handleInfos, handleInfoSize, NULL)) == 0xc0000004)
		handleInfos = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfos, handleInfoSize *= 2);

	if (!NT_SUCCESS(status)) {
		return vec;
	}

	HANDLE copy = 0;

	for (int i = 0; i < handleInfos->HandleCount; i++)
	{
		SYSTEM_HANDLE handleInfo = handleInfos->Handles[i];

		HANDLE proc_Handle = OpenProcess(PROCESS_DUP_HANDLE, 0, handleInfo.ProcessId);

		if (!proc_Handle) {
			continue;
		}

		if ((handleInfo.GrantedAccess & access_mask) == access_mask) {
			if (DuplicateHandle(proc_Handle, reinterpret_cast<HANDLE>(handleInfo.Handle), GetCurrentProcess(), &copy, PROCESS_QUERY_INFORMATION, 0, 0)) {
				if (GetProcessId(copy) == pid) {
					vec.push_back(std::shared_ptr<HandleInformation>(new HandleInformation(handleInfo.ProcessId, GetProcessId(copy), handleInfo.GrantedAccess, handleInfo.Handle)));
				}
			}
		}

		if (copy)
			CloseHandle(copy);

		if (proc_Handle)
			CloseHandle(proc_Handle);
	}

	return vec;
}