#include <Windows.h>
#include <iostream>
#include <LoadLibInjection.h>
#include <WinHandle.h>
#include <PEFile.h>
#include <PatternScanner.h>
#include <Detour.h>
#include <Console.h>
#include <MMap.h>
#include <Driver.h>
using WinLib::PE::Loader::LoadLibInjection;
using WinLib::PE::PEFile;
using WinLib::Mem::PatternScanner;
using WinLib::Mem::Hook::Detour;
using WinLib::Output::Console;
using WinLib::Output::LogType;
using WinLib::PE::Loader::MMapper;
using WinLib::PE::Loader::Driver;

BOOL SetPrivilege(
	HANDLE hToken,          // token handle
	LPCTSTR Privilege,      // Privilege to enable/disable
	BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
);

bool EnablePrivilege(
	LPCWSTR lpPrivilegeName
)
{
	TOKEN_PRIVILEGES Privilege;
	HANDLE hToken;
	DWORD dwErrorCode;

	Privilege.PrivilegeCount = 1;
	Privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!LookupPrivilegeValueW(NULL, lpPrivilegeName,
		&Privilege.Privileges[0].Luid))
		return GetLastError();

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES, &hToken))
		return GetLastError();

	if (!AdjustTokenPrivileges(hToken, FALSE, &Privilege, sizeof(Privilege),
		NULL, NULL)) {
		dwErrorCode = GetLastError();
		CloseHandle(hToken);
		return dwErrorCode;
	}

	CloseHandle(hToken);
	return TRUE;
}

BOOL SetPrivilege(
	HANDLE hToken,          // token handle
	LPCTSTR Privilege,      // Privilege to enable/disable
	BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;

	// 
	// first pass.  get current privilege setting
	// 
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious
	);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	// 
	// second pass.  set privilege based on previous setting
	// 
	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = luid;

	if (bEnablePrivilege) {
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}
	else {
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
			tpPrevious.Privileges[0].Attributes);
	}

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL
	);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	return TRUE;
}

void testDriver() {
	auto driver = new Driver("C:\\Users\\Thomas\\source\\repos\\KernelDriver\\x64\\Release\\KernelDriver.sys");

	if (!driver->load()) {
		Console::printLog(LogType::ERR, "Driver load failed!");
		return;
	}

	Console::printLog(LogType::INFO, "Driver loaded!");
	Console::printLog(LogType::INFO, "Press a key to unload!");
	getchar();

	if (!driver->unload()) {
		Console::printLog(LogType::ERR, "Driver unload failed!");
		return;
	}

	Console::printLog(LogType::INFO, "Driver unloaded!");
}

int main(int argc, char **argv) {
	if (!EnablePrivilege(L"SeLoadDriverPrivilege"))
	{
		Console::printLog(LogType::ERR, "Setting driver privilege failed");
	}

	testDriver();

	getchar();
	return 0;
}