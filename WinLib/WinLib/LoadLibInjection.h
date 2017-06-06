#pragma once
#include <Windows.h>
#include <string>
#include "WinProcess.h"

namespace WinLib {
	namespace PE {
		namespace Loader {
			class LoadLibInjection {
			private:
				typedef struct _CLIENT_ID
				{
					PVOID UniqueProcess;
					PVOID UniqueThread;
				} CLIENT_ID, *PCLIENT_ID;

				typedef long(*RtlCreateUserThread)(HANDLE,PSECURITY_DESCRIPTOR,BOOLEAN, ULONG,PULONG, PULONG,PVOID, PVOID,PHANDLE,PCLIENT_ID);
				RtlCreateUserThread pRtlCreateUserThread;

				static LoadLibInjection* _instance;
				LoadLibInjection();
			public:
				enum Type {
					CREATETHREAD,
					RTLCREATEUSERTHREAD
				};

				static LoadLibInjection* getInstance();

				bool inject(const std::string& processName, const std::string& path, Type type);
				bool inject(DWORD pid, const std::string& path, Type type);
			};
		}
	}
}