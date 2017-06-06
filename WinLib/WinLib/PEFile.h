#pragma once
#include <iostream>
#include <Windows.h>

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
			byte* sectionBase;
		public:
			PEFile(char* rawData, int rawDatSize);
			PEFile(const std::string& moduleName);
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
			byte* getSectionBase(int num);
			byte* getCodeBase();
			int getCodeSize();

			PIMAGE_NT_HEADERS getNtHeader();
			PIMAGE_DOS_HEADER getDosHeader();
			PIMAGE_SECTION_HEADER getSectionHeader();
			PIMAGE_BASE_RELOCATION getBaseRelocation();
			PIMAGE_IMPORT_DESCRIPTOR getImportDescriptor();
		};
	}
}