#pragma once
#include <Windows.h>
#include <stdint.h>
#include <string>
#include "PEFile.h"

namespace WinLib {
	namespace Mem {
		class PatternScanner {
		private:
			static uint8_t* search_internal();
		public:
			static uint8_t* search(std::string moduleName);
			static uint8_t* search();
		};
	}
}