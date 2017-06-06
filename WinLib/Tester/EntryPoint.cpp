#include <Windows.h>
#include <iostream>
#include <LoadLibInjection.h>
#include <WinHandle.h>
#include <PEFile.h>

using WinLib::PE::Loader::LoadLibInjection;
using WinLib::PE::PEFile;

BOOL SetPrivilege(
	HANDLE hToken,          // token handle
	LPCTSTR Privilege,      // Privilege to enable/disable
	BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
);

void adjustPrivileges() {
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;

	if (OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		tp.Privileges[0].Luid.LowPart = 20;
		tp.Privileges[0].Luid.HighPart = 0;

		AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
		if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
		{
			CloseHandle(hToken);

			return;
		}

		CloseHandle(hToken);
	}
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

int main(int argc, char **argv) {
	adjustPrivileges();

	//if (LoadLibInjection::getInstance()->inject(536, std::string("C:\\Users\\TomLadder\\MMap\\MMap\\x64\\Release\\HandleHijackMMap.dll"), LoadLibInjection::Type::RTLCREATEUSERTHREAD)) {
	//	std::cout << "Injection success" << std::endl;
	//}
	//else {
	//	std::cout << "Injection failed" << std::endl;
	//}

	auto pe = PEFile::PEFile();
	std::cout << std::hex << (uint64_t) pe.getCodeBase() << std::endl;

	getchar();
	return 0;
}