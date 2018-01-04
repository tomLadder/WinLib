#pragma once
#include <ntddk.h>

namespace WinLibKernel {
	namespace Mem {
		namespace Hook {
			enum HookType {
				JMP
			};

			class Hook {
			private:

				HookType type;
				UINT8* src;
				UINT8* dst;

			public:
				Hook(HookType type, UINT8* src, UINT8* dst);

				HookType getType();
				UINT8* getSrc();
				UINT8* getDst();
			};
		}
	}
}