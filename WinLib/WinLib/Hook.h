#pragma once
#include <stdint.h>
#include <Windows.h>

namespace WinLib {
	namespace Mem {
		namespace Hook {
			enum HookType {
				JMP
			};

			class Hook {
			private:

				HookType type;
				uint8_t* src;
				uint8_t* dst;

			public:
				Hook(HookType type, uint8_t* src, uint8_t* dst);

				virtual void hook() = 0;
				virtual void unhook() = 0;

				HookType getType();
				uint8_t* getSrc();
				uint8_t* getDst();
			};
		}
	}
}