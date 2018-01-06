#include "Detour.h"

using WinLibKernel::Mem::Hook::Detour;
using WinLibKernel::Mem::cr0;

Detour::Detour(UINT8* src, UINT8* dst)
	: Hook(HookType::JMP, src, dst) {

}

Detour::~Detour() {
	if(this->isHooked)
		delete this->trampoline;
}

void Detour::hook() {
	ldasm_data ld;

	this->trampoline_size = ldasm(this->getSrc(), &ld, true);
	while (this->trampoline_size < Detour::length_jmp) {
		this->trampoline_size += ldasm(this->getSrc() + this->trampoline_size, &ld, true);
	}

	auto dest = this->getSrc() + this->trampoline_size;
	auto highPart = (INT32)((INT64)dest >> 32);

	this->trampoline = new (NonPagedPool) UINT8[this->trampoline_size + Detour::length_jmp];
	memcpy(this->trampoline, this->getSrc(), this->trampoline_size);
	memcpy(this->trampoline + this->trampoline_size, Detour::jmp_machine_code, Detour::length_jmp);
	memcpy(this->trampoline + this->trampoline_size + 1, &dest, 4);
	memcpy(this->trampoline + this->trampoline_size + 9, &highPart, 4);

	auto kirql = cr0::wp_off();

	dest = this->getDst();
	highPart = (UINT32)((UINT64)dest >> 32);

	//Place JMP
	memcpy(this->getSrc(), Detour::jmp_machine_code, Detour::length_jmp);
	memcpy(this->getSrc() + 1, &dest, 4);
	memcpy(this->getSrc() + 9, &highPart, 4);

	//Fill empty space
	int nopcnt = this->trampoline_size - Detour::length_jmp;
	if (nopcnt > 0) {
		memset(this->getSrc() + Detour::length_jmp, 0x90, nopcnt);
	}
	
	cr0::wp_on(kirql);

	this->isHooked = TRUE;
}

void Detour::unhook() {
	auto kirql = cr0::wp_off();

	memcpy(this->getSrc(), this->trampoline, this->trampoline_size);
	delete trampoline;

	cr0::wp_on(kirql);

	this->isHooked = FALSE;
}

UINT8* Detour::getTrampoline() {
	return this->trampoline;
}