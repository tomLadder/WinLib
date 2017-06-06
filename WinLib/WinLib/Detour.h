#pragma once
#include "capstone\include\capstone.h"
#include "Hook.h"
#include <iostream>
#include "WinThread.h"

namespace WinLib {
	namespace Mem {
		namespace Hook {
			class Detour : public Hook {
			private:
				static int constexpr length_jmp = 14;

				//PUSH lowerPart
				//MOV [RSP+4], higherPart
				//RET
				static constexpr char* jmp_machine_code = "\x68\x00\x00\x00\x00\xC7\x44\x24\x04\x00\x00\x00\x00\xC3";

				int trampoline_size = 0;
				uint8_t* trampoline;
			public:
				Detour(uint8_t* src, uint8_t* dst);

				void hook();
				void unhook();

				uint8_t* getTrampoline();
			};
		}
	}
}