#pragma once
#include <Windows.h>
#include <iostream>
#include "RawData.h"
#include "PEFile.h"

using WinLib::PE::PEFile;

namespace WinLib {
	namespace Communication {
		namespace Raw {
			class PEData : public RawData {
			private:
				static constexpr int uint32_t = 0x1;
				uint8_t* pe;
			public:
				PEData(uint8_t* pe, uint64_t size);
				PEData(PEFile* peFile);
			};
		}

	}

}