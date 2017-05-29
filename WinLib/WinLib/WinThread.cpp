#include "WinThread.h"

std::vector<THREADENTRY32> WinLib::WinThread::getThreadsInternal(bool ownOnly) {
	std::vector<THREADENTRY32> vec;
	HANDLE threadHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (threadHandle == INVALID_HANDLE_VALUE)
		return vec;

	int pid = GetCurrentProcessId();

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(threadHandle, &threadEntry)) {
		do {
			if (ownOnly && threadEntry.th32OwnerProcessID != pid)
				continue;

			vec.push_back(threadEntry);
		} while (Thread32Next(threadHandle, &threadEntry));
	}

	return vec;
}

std::vector<THREADENTRY32> WinLib::WinThread::getThreads() {
	return WinLib::WinThread::getThreadsInternal(false);
}

std::vector<THREADENTRY32> WinLib::WinThread::getOwnThreads() {
	return WinLib::WinThread::getThreadsInternal(true);
}

void WinLib::WinThread::suspendThreads() {
	auto threads = WinLib::WinThread::getOwnThreads();
	auto currentThreadId = GetCurrentThreadId();

	for (auto thread : threads) {
		if (thread.th32ThreadID == currentThreadId)
			continue;

		HANDLE threadHandle = OpenThread(THREAD_SUSPEND_RESUME, 0, thread.th32ThreadID);
		if (threadHandle) {
			SuspendThread(threadHandle);
		}

		CloseHandle(threadHandle);
	}
}

void WinLib::WinThread::resumeThreads() {
	auto threads = WinLib::WinThread::getOwnThreads();

	for (auto thread : threads) {
		HANDLE threadHandle = OpenThread(THREAD_SUSPEND_RESUME, 0, thread.th32ThreadID);
		if (threadHandle) {
			while(ResumeThread(threadHandle) > 0)
				ResumeThread(threadHandle);
		}

		CloseHandle(threadHandle);
	}
}