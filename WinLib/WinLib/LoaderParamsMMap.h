#pragma once
#include <Windows.h>

typedef FARPROC(WINAPI *fGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE(WINAPI *fLoadLibrary)(LPCTSTR lpFileName);
typedef BOOL(WINAPI *fDllMain)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

struct LoaderParamsMMap {
	fGetProcAddress addr_GetProcAdress;
	fLoadLibrary addr_LoadLibrary;
	fDllMain addr_DllMain;
	byte* mapped_PE;
	DWORD imports_VA;
};