#include "HandleInformation.h"

using WinLib::HandleInformation;

HandleInformation::HandleInformation(DWORD _hostPid, DWORD _handlePID, DWORD _accessMask, USHORT _handle) {
	this->hostPid = _hostPid;
	this->handlePid = _handlePID;
	this->accessMask = _accessMask;
	this->handle = _handle;
}

DWORD HandleInformation::getHostPid() {
	return this->hostPid;
}

DWORD HandleInformation::getHandlePid() {
	return this->handle;
}

DWORD HandleInformation::getAccessMask() {
	return this->accessMask;
}

USHORT HandleInformation::getHandle() {
	return this->handle;
}