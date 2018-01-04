#pragma once
#include "ldasm.h"
#include "Hook.h"
#include "winstructs.h"
#include "memory.h"
#include "cr0.h"
#include <intrin.h>

namespace WinLibKernel {
	namespace Mem {
		namespace Hook {
			class Detour : public Hook {
			private:
				static int constexpr length_jmp = 14;

				//PUSH lowerPart
				//MOV [RSP+4], higherPart
				//RET
				//Investigate in this issue
				const char* jmp_machine_code = "\x68\x00\x00\x00\x00\xC7\x44\x24\x04\x00\x00\x00\x00\xC3";


				int trampoline_size = 0;
				UINT8* trampoline;
			public:
				Detour(UINT8* src, UINT8* dst);
				~Detour();

				void hook();
				void unhook();

				UINT8* getTrampoline();
			};
		}
	}
}