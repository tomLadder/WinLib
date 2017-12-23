#pragma once
#include <Windows.h>
#include <iostream>

namespace WinLib {
	namespace Communication {
		namespace Raw {
			class RawData {
			protected:
				uint32_t type;
				uint64_t size;
			public:
				RawData(uint32_t type, uint64_t size);
			};
		}
	}
}