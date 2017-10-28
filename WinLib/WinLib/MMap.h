#pragma once
#include <Windows.h>
#include "PEFile.h"
#include "LoaderParamsMMap.h"

namespace WinLib {
	namespace PE {
		namespace Loader {
			class MMapper {
			private:
				PEFile* peFile;
				byte* payload;

				bool mapHeader();
				bool mapSections();
				bool baseRelocation(ULONG_PTR targetBase);
				PIMAGE_BASE_RELOCATION processRelocation(ULONG_PTR address, ULONG count, PUSHORT typeOffset, LONGLONG delta);
				bool setProtectionFlags();
				bool writeToProcess(HANDLE processHandle, LPVOID memBase, int size);
				bool writeLoaderParamsToProcess(HANDLE processHandle, LPVOID loaderMemory, LPVOID peBase);
				bool executePayload(HANDLE processHandle, LPVOID peBase);
			public:
				enum STATUS {
					SUCCESS,
					FAILED,
					ACCESSDENIED,
					PEINVALID
				};

				MMapper(PEFile* peFile);
				STATUS map(DWORD pid);
				STATUS map(HANDLE handle);
				STATUS mapInternal(HANDLE handle);
			};
		}
	}
}