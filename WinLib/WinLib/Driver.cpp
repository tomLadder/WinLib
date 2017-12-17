#include "Driver.h"

using WinLib::PE::Loader::Driver;

Driver::Driver(std::wstring path, std::wstring displayname) {
	this->path = path;
	this->displayname = displayname;
	
	std::hash <std::wstring> hash_fn;
	this->hash = hash_fn(this->path);

	auto handle									= GetModuleHandle("ntdll.dll");
	*(FARPROC *)&this->NtLoadDriver				= GetProcAddress(handle, "NtLoadDriver");
	*(FARPROC *)&this->NtUnloadDriver			= GetProcAddress(handle, "NtUnloadDriver");
	*(FARPROC *)&this->RtlInitUnicodeString		= GetProcAddress(handle, "RtlInitUnicodeString");
	*(FARPROC *)&this->RtlFreeUnicodeString		= GetProcAddress(handle, "RtlFreeUnicodeString");
}

bool Driver::load() {
	UNICODE_STRING path;

	if (!create_regentry())
		return false;

	wchar_t buf[1024];
	wcscpy_s(buf, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
	
	wcscat_s(buf, std::to_wstring(this->hash).c_str());

	this->RtlInitUnicodeString(&path, buf);
	auto code = this->NtLoadDriver(&path);
	if (code != STATUS_SUCCESS) {
		return false;
	}

	remove_regentry();

	return true;
}

bool Driver::unload() {
	UNICODE_STRING path;
	wchar_t buf[1024];

	if (!create_regentry())
		return false;

	wcscpy_s(buf, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
	wcscat_s(buf, std::to_wstring(this->hash).c_str());

	this->RtlInitUnicodeString(&path, buf);

	auto code = this->NtUnloadDriver(&path);
	if (code != STATUS_SUCCESS) {
		return false;
	}

	remove_regentry();

	return true;
}

bool Driver::create_regentry() {
	HKEY phkResult = NULL;
	DWORD start = 0;
	DWORD type = 3;
	std::wstring imagepath = std::wstring(L"\\??\\").append(this->path);

	auto errCode = RegCreateKeyExW(HKEY_LOCAL_MACHINE, std::wstring(L"System\\CurrentControlSet\\Services\\").append(std::to_wstring(this->hash).c_str()).c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &phkResult, NULL);
	if (errCode) {
		RegCloseKey(phkResult);
		return false;
	}
	
	if (RegSetValueExW(phkResult, L"Start", 0, REG_DWORD, (const BYTE *)&start, sizeof(DWORD)) != ERROR_SUCCESS) {
		RegCloseKey(phkResult);
		return false;
	}

	if (RegSetValueExW(phkResult, L"Type", 0, REG_DWORD, (const BYTE *)&type, sizeof(DWORD)) != ERROR_SUCCESS) {
		RegCloseKey(phkResult);
		return false;
	}

	if (RegSetValueExW(phkResult, L"ImagePath", 0, REG_SZ, (const BYTE *)imagepath.c_str(), imagepath.size() * sizeof(WCHAR)) != ERROR_SUCCESS) {
		RegCloseKey(phkResult);
		return false;
	}

	if (RegSetValueExW(phkResult, L"DisplayName", 0, REG_SZ, (const BYTE *)this->displayname.c_str(), imagepath.size() * sizeof(CHAR)) != ERROR_SUCCESS) {
		RegCloseKey(phkResult);
		return false;
	}

	RegCloseKey(phkResult);

	return true;
}

bool Driver::remove_regentry() {
	HKEY phkResult = NULL;
	DWORD start = 0;
	DWORD type = 3;
	std::wstring imagepath = std::wstring(L"\\??\\").append(this->path);

	auto errCode = RegDeleteKeyExW(HKEY_LOCAL_MACHINE, std::wstring(L"System\\CurrentControlSet\\Services\\").append(std::to_wstring(this->hash).c_str()).c_str(), KEY_ALL_ACCESS, 0);
	if (errCode) {
		RegCloseKey(phkResult);
		return false;
	}

	RegCloseKey(phkResult);
	return true;
}