#pragma once
#include <Windows.h>
#include <string>

namespace WinLib {
	class ProcessInformation {
	private:
		DWORD pid;
		std::string name;
		bool wow64;
	public:
		ProcessInformation(DWORD _pid, std::string _name, bool _wow64);

		DWORD getPid();
		std::string getName();
		bool isWow64();
	};
};