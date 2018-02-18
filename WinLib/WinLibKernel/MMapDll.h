#pragma once
#include <ntifs.h>
#include "PEFile.h"
#include "ntos.h"

namespace WinLibKernel {
	namespace PE {
		namespace Loader {
			class MMapperDll {
			public:
				enum STATUS {
					SUCCESS,
					FAILED,
					ACCESSDENIED,
					PEINVALID
				};

				MMapperDll(PEFile *peFile);

				STATUS map(PEPROCESS process, PVOID originalEntryPoint, PVOID targetBase, DWORD64 targetSize);
			private:
				PEFile * peFile;
				PVOID payload;

				bool mapHeader();
				bool mapSections();
				bool baseRelocation(PVOID targetBase);
				bool fixImports();
				bool writeToProcess(PEPROCESS process, PVOID targetBase, DWORD64 targetSize);
				bool patchEntryPoint(PVOID originalEntryPoint);

				PIMAGE_BASE_RELOCATION processRelocation(ULONG_PTR address, ULONG count, PUSHORT typeOffset, LONGLONG delta);
			};
		}
	}
}