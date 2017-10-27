#include "Vmt.h"

using WinLib::Mem::Hook::Vmt;

Vmt::Vmt(uint64_t** _vtable, uint32_t _index, uint64_t* _dst) {
	this->vtable = _vtable;
	this->index = _index;
	this->dst = _dst;
}

uint64_t* Vmt::hook() {
	DWORD protection;

	VirtualProtect(&this->vtable[index], sizeof(uint64_t), PAGE_EXECUTE_READWRITE, &protection);
	this->old = this->vtable[index];
	this->vtable[index] = this->dst;
	VirtualProtect(&this->vtable[index], sizeof(uint64_t), protection, &protection);

	return this->old;
}

void Vmt::unhook() {
	if (this->old != nullptr) {
		DWORD protection;

		VirtualProtect(&this->vtable[index], sizeof(uint64_t), PAGE_EXECUTE_READWRITE, &protection);
		this->vtable[index] = this->old;
		VirtualProtect(&this->vtable[index], sizeof(uint64_t), protection, &protection);
	}
}

uint64_t** Vmt::getVTable() {
	return this->vtable;
}

uint32_t Vmt::getIndex() {
	return this->index;
}

uint64_t* Vmt::getDst() {
	return this->dst;
}

uint64_t* Vmt::getOld() {
	return this->old;
}