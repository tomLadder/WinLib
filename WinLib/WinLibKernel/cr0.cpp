#include "cr0.h"

using WinLibKernel::Mem::cr0;

KIRQL cr0::wp_off() {
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	CLR_BIT(cr0, 16);
	__writecr0(cr0);
	_disable();
	return irql;
}

VOID cr0::wp_on(KIRQL irql) {
	UINT64 cr0 = __readcr0();
	SET_BIT(cr0, 16);
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}