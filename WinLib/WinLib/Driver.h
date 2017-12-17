#pragma once
#include <Windows.h>
#include <string>
#include <Subauth.h>
#include <iostream>

namespace WinLib {
	namespace PE {
		namespace Loader {
			class Driver {
			private:
				std::wstring path;
				std::wstring displayname;
				size_t hash;

				NTSTATUS (NTAPI *NtLoadDriver)(_In_ PUNICODE_STRING DriverServiceName);
				VOID (NTAPI *RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
				NTSTATUS (NTAPI *NtUnloadDriver)(IN PUNICODE_STRING DriverServiceName);
				VOID (NTAPI *RtlFreeUnicodeString)(_Inout_ PUNICODE_STRING UnicodeString);


				bool create_regentry();
				bool remove_regentry();
			public:
				Driver(std::wstring path, std::wstring displayname);

				bool load();
				bool unload();
			};
		}
	}
}