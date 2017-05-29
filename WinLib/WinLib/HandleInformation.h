#pragma once
#include <Windows.h>

namespace WinLib {
	class HandleInformation {
	private:
		DWORD hostPid;
		DWORD handlePid;
		DWORD accessMask;
		USHORT handle;
	public:
		HandleInformation(DWORD _hostPid, DWORD _handlePID, DWORD _accessMask, USHORT _handle);

		DWORD getHostPid();
		DWORD getHandlePid();
		DWORD getAccessMask();
		USHORT getHandle();
	};
}