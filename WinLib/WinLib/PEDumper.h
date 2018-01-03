#pragma once
#include "PEFile.h"

namespace WinLib {
	namespace PE {
		class PEDumper {
		public:
			PEDumper();
			PEDumper(PEFile *dumper, std::string name);
			PEDumper(const std::string& path, std::string name);
		private:
			PEFile *original;
			std::string name;
		};
	}
}