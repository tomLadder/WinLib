#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <memory>

#include "ProcessInformation.h"

using WinLib::ProcessInformation;

namespace WinLib {
	class WinProcess {
	public:
		static DWORD findProcessId(const std::string& processName);
		static std::vector<std::shared_ptr<ProcessInformation>> getProcesses();
	};
};