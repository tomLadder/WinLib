#include <Windows.h>
#include <iostream>
#include <WinThread.h>

using WinLib::WinThread;

int main() {
	WinThread::suspendThreads();
	std::cout << "Suspended!" << std::endl;
	WinThread::resumeThreads();

	getchar();
	return 0;
}