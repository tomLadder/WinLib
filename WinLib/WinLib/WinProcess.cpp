#include "WinProcess.h"

using WinLib::WinProcess;

DWORD WinProcess::findProcessId(const std::string& processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}
	return 0;
}

std::vector<std::shared_ptr<ProcessInformation>> WinProcess::getProcesses() {
	std::vector <std::shared_ptr<ProcessInformation>> vec;

	auto handleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

	if (handleSnapshot == INVALID_HANDLE_VALUE)
		return vec;

	PROCESSENTRY32 procEntry = {};
	procEntry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(handleSnapshot, &procEntry)) {
		do {
			bool isWow64 = false;

			HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, 0, procEntry.th32ProcessID);

			if (h) {
				BOOL wow64Process = true;
				if (IsWow64Process(h, &wow64Process))
					isWow64 = true;
				CloseHandle(h);
			}

			vec.push_back(std::shared_ptr<ProcessInformation>(new ProcessInformation(procEntry.th32ProcessID, std::string(procEntry.szExeFile), isWow64)));
		} while (Process32Next(handleSnapshot, &procEntry));
	}

	CloseHandle(handleSnapshot);

	return vec;
}