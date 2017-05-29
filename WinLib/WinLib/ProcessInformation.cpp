#include "ProcessInformation.h"

using WinLib::ProcessInformation;

ProcessInformation::ProcessInformation(DWORD _pid, std::string _name, bool _wow64) {
	this->pid = _pid;
	this->name = _name;
	this->wow64 = _wow64;
}

DWORD ProcessInformation::getPid() {
	return this->pid;
}

std::string ProcessInformation::getName() {
	return this->name;
}

bool ProcessInformation::isWow64() {
	return this->wow64;
}	