#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <vector>
#include <iostream>

namespace WinLib {
	class WinThread {
	private:
		static std::vector<THREADENTRY32> getThreadsInternal(bool ownOnly);
	public:
		static std::vector<THREADENTRY32> getThreads();
		static std::vector<THREADENTRY32> getOwnThreads();
		static void suspendThreads();
		static void resumeThreads();
	};
}