#pragma once
#include <stdint.h>
#include <Windows.h>

namespace WinLib {
	namespace Mem {
		namespace Hook {

			class Vmt {
			private:
				uint64_t** vtable = nullptr;
				uint32_t index = 0;
				uint64_t* dst = nullptr;
				uint64_t* old = nullptr;

			public:
				Vmt(uint64_t** _vtable, uint32_t _index, uint64_t* _dst);

				uint64_t* hook();
				void unhook();

				uint64_t** getVTable();
				uint32_t getIndex();
				uint64_t* getDst();
				uint64_t* getOld();
			};
		}
	}
}