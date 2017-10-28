#include <Windows.h>
#include <iostream>
#include <LoadLibInjection.h>
#include <WinHandle.h>
#include <PEFile.h>
#include <PatternScanner.h>
#include <Detour.h>
#include <Console.h>
#include <MMap.h>

using WinLib::PE::Loader::LoadLibInjection;
using WinLib::PE::PEFile;
using WinLib::Mem::PatternScanner;
using WinLib::Mem::Hook::Detour;
using WinLib::Output::Console;
using WinLib::Output::LogType;
using WinLib::PE::Loader::MMapper;

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

void func();
void func2();

typedef void(*_func)();
_func pfunc;

void manualmap() {
	//auto pe = PEFile::loadFromFile("C:\\Users\\Thomas\\source\\repos\\EmptyDll\\x64\\Release\\EmptyDll.dll");
	//C:\Dev\dxlib\dxlib\x64\Release
	auto pe = PEFile::loadFromFile("C:\\Dev\\dxlib\\dxlib\\x64\\Release\\dx11.dll");
	if (pe) {
		Console::printLog(LogType::DEBUG, "PEFile found");
		
		MMapper* mapper = new MMapper(pe);

		if (mapper->map(5708)) {
			Console::printLog(LogType::DEBUG, "PE mapped into target process");
		}
		else {
			Console::printLog(LogType::WARN, "Could not mapp PE into target process");
		}
	}
	else {
		Console::printLog(LogType::WARN, "Could not read PE-File");
	}
}

int main(int argc, char **argv) {
	adjustPrivileges();

	manualmap();

	//func();

	//auto mask = "xxxxxxx????xxx????x????xxx????xxxxx????xxx?????xxx????";
	//auto pattern = "\x48\x83\xEC\x38\x48\x8D\x15\x00\x00\x00\x00\x48\x8B\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8D\x15\x00\x00\x00\x00\x48\x8B\xC8\xFF\x15\x00\x00\x00\x00\xC7\x44\x24\x00\x00\x00\x00\x00\x48\x8D\x15\x00\x00\x00\x00";

	//auto addr = PatternScanner::search(pattern, mask);

	//std::cout << std::hex << (uint64_t)addr << std::endl;

	//auto detour = new Detour(addr, (uint8_t*)&func2);
	//detour->hook();
	//pfunc = (_func)detour->getTrampoline();

	//std::cout << (uint64_t)detour->getTrampoline() << std::endl;

	//std::cout << "Press a key to continue" << std::endl;
	//getchar();
	//func();

	getchar();
	return 0;
}

void func() {
	std::cout << "hello world" << std::endl;

	int x = 24 * 232;
	std::cout << "Addr: " << x << std::endl;
}

void func2() {
	std::cout << "hooked" << std::endl;
	pfunc();
}