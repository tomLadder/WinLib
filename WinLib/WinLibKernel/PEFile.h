#pragma once

#include <ntddk.h>
#include "Debug.h"
#include "winstructs.h"

namespace WinLib {
	namespace PE {
		class PEFile {
		private:
			bool isInMemory;
			int rawDataSize;
			char* rawData;
			PIMAGE_NT_HEADERS ntHeader;
			PIMAGE_DOS_HEADER dosHeader;
			PIMAGE_SECTION_HEADER sectionHeader;
			CHAR* sectionBase;
		public:
			PEFile(char* rawData, int rawDatSize);
			PEFile();

			bool isValid();
			void printInfos();
			void printSections();
			int getRawDataSize();
			char* getRawData();
			int getImageSize();
			int getHeaderSize();
			int getNumberOfSections();
			PIMAGE_SECTION_HEADER getSectionHeader(int num);
			CHAR* getSectionBase(int num);
			CHAR* getCodeBase();
			int getCodeSize();

			PIMAGE_NT_HEADERS getNtHeader();
			PIMAGE_DOS_HEADER getDosHeader();
			PIMAGE_SECTION_HEADER getSectionHeader();
			PIMAGE_BASE_RELOCATION getBaseRelocation();
			PIMAGE_IMPORT_DESCRIPTOR getImportDescriptor();
		};
	}
}