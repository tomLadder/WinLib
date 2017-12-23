#include "RawMemoryCommunication.h"

using WinLib::Communication::Raw::RawMemoryCommunication;

RawMemoryCommunication::RawMemoryCommunication() {
	this->internalBuffer = nullptr;
}

RawMemoryCommunication::~RawMemoryCommunication() {
	this->thread.detach();
	delete this->internalBuffer;
	this->internalBuffer = nullptr;
}

bool RawMemoryCommunication::init() {
	this->internalBuffer = new InternalBuffer();

	if (this->internalBuffer) {
		this->thread = std::thread(&RawMemoryCommunication::internal_thread, this);

		return this->setState(STATE::WAIT);
	}

	return false;
}

bool RawMemoryCommunication::setState(RawMemoryCommunication::STATE state) {
	if (!this->internalBuffer)
		return false;

	memcpy(this->internalBuffer, &state, sizeof(STATE));

	if (this->callback)
		this->callback(reinterpret_cast<InternalBuffer*>(this->internalBuffer));

	return true;
}

bool RawMemoryCommunication::registerCallback(RawMemoryCommunication::event_callback callback) {
	this->callback = callback;

	return true;
}

void RawMemoryCommunication::internal_thread() {
	while (1) {

		if (this->internalBuffer) {
			if (this->internalBuffer->state == NEW && this->callback)
				callback(this->internalBuffer);
		}

		Sleep(100);
	}
}

LPVOID RawMemoryCommunication::getInternalAdress() {
	return reinterpret_cast<LPVOID>(this->internalBuffer);
}