#include "Detour.h"

using WinLib::Mem::Hook::Detour;

Detour::Detour(uint8_t* src, uint8_t* dst)
	: Hook(HookType::JMP, src, dst) {

}

void Detour::hook() {
	WinLib::WinThread::suspendThreads();

	csh capstoneHandle;
	DWORD protection = 0;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstoneHandle) != CS_ERR_OK)
		return;

	cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_insn* instructions;

	cs_disasm(capstoneHandle, this->getSrc(), 0x200, (uint64_t)this->getSrc(), 0, &instructions);

	int i = 0;
	while (this->trampoline_size <= Detour::length_jmp) {
		auto instruction = (cs_insn*)(&instructions[i]);
		this->trampoline_size += instruction->size;

		i++;
	}

	auto dest = this->getSrc() + this->trampoline_size;
	auto highPart = (int32_t)((uint64_t)dest >> 32);

	this->trampoline = new uint8_t[this->trampoline_size + Detour::length_jmp];
	memcpy(this->trampoline, this->getSrc(), this->trampoline_size);
	memcpy(this->trampoline + this->trampoline_size, Detour::jmp_machine_code, Detour::length_jmp);
	memcpy(this->trampoline + this->trampoline_size + 1, &dest, 4);
	memcpy(this->trampoline + this->trampoline_size + 9, &highPart, 4);

	VirtualProtect(this->trampoline, this->trampoline_size + Detour::length_jmp, PAGE_EXECUTE_READWRITE, &protection);

	dest = this->getDst();
	highPart = (int32_t)((uint64_t)dest >> 32);

	VirtualProtect(this->getSrc(), this->trampoline_size, PAGE_EXECUTE_READWRITE, &protection);

	//Place JMP
	memcpy(this->getSrc(), Detour::jmp_machine_code, Detour::length_jmp);
	memcpy(this->getSrc() + 1, &dest, 4);
	memcpy(this->getSrc() + 9, &highPart, 4);

	//Fill empty space
	int nopcnt = this->trampoline_size - Detour::length_jmp;
	if (nopcnt > 0) {
		memset(this->getSrc() + Detour::length_jmp, 0x90, nopcnt);
	}
	VirtualProtect(this->getSrc(), this->trampoline_size, protection, &protection);

	cs_close(&capstoneHandle);

	WinLib::WinThread::resumeThreads();
}

void Detour::unhook() {
	WinLib::WinThread::suspendThreads();

	DWORD protection;
	VirtualProtect(this->getSrc(), this->trampoline_size, PAGE_EXECUTE_READWRITE, &protection);

	memcpy(this->getSrc(), this->trampoline, this->trampoline_size);
	delete trampoline;

	VirtualProtect(this->getSrc(), this->trampoline_size, protection, &protection);

	WinLib::WinThread::resumeThreads();
}

uint8_t* Detour::getTrampoline() {
	return this->trampoline;
}