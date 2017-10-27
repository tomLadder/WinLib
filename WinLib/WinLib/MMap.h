#pragma once
#include <Windows.h>
#include "PEFile.h"
#include "LoaderParamsMMap.h"


#define RVA	(m,b) ((PVOID)((ULONG_PTR)(b)+(ULONG_PTR)(m)))

namespace WinLib {
	namespace PE {
		namespace Loader {
			class MMapper {
			private:
				PEFile* peFile;
				byte* payload;

				bool mapHeader();
				bool mapSections();
				bool baseRelocation();
				bool setProtectionFlags();
				bool writeToProcess(HANDLE processHandle, LPVOID memBase, int size);
				bool writeLoaderParamsToProcess(HANDLE processHandle, LPVOID loaderMemory, LPVOID peBase);
				bool executePayload(HANDLE processHandle, LPVOID peBase);
			public:
				MMapper(PEFile* peFile);
				bool map(DWORD pid);
				bool map(HANDLE handle);
				bool mapInternal(HANDLE handle);
			};
		}
	}
}