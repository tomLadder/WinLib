#include "LoadLibInjection.h"

using WinLib::PE::Loader::LoadLibInjection;

LoadLibInjection* LoadLibInjection::_instance = nullptr;

LoadLibInjection* LoadLibInjection::getInstance() {
	if (_instance == nullptr) {
		_instance = new LoadLibInjection();
	}

	return _instance;
}

LoadLibInjection::LoadLibInjection() {
	this->pRtlCreateUserThread = (RtlCreateUserThread)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCreateUserThread");
}

bool LoadLibInjection::inject(const std::string& processName, const std::string& path, Type type) {
	auto pid = WinProcess::findProcessId(processName);

	if (pid == 0)
		return false;

	return LoadLibInjection::inject(pid, path, type);
}

bool LoadLibInjection::inject(DWORD pid, const std::string& path, Type type) {
	auto handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

	if (!handle)
		return false;

	auto mem = VirtualAllocEx(handle, 0, path.size() * sizeof(char), MEM_COMMIT, PAGE_READWRITE);

	if (!mem) {
		CloseHandle(handle);
		return false;
	}

	if (!WriteProcessMemory(handle, mem, path.c_str(), path.size() * sizeof(char), 0)) {
		CloseHandle(handle);
		return false;
	}

	HANDLE threadHandle = 0;
	LoadLibInjection::CLIENT_ID cid;

	if(type == RTLCREATEUSERTHREAD)
		this->pRtlCreateUserThread(handle, 0, 0, 0, 0, 0, reinterpret_cast<PVOID>(&LoadLibraryA), mem, &threadHandle, &cid);
	else if (type == CREATETHREAD)
		threadHandle = CreateRemoteThread(handle, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(&LoadLibraryA), mem, 0, 0);

	WaitForSingleObject(threadHandle, INFINITE);
	VirtualFree(mem, path.size() * sizeof(wchar_t), MEM_FREE);
	CloseHandle(handle);

	return true;
}