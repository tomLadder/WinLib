#pragma once
#include <ntddk.h>
#include <intrin.h>

#define SET_BIT(x, n) x |= (1U << (n));
#define CLR_BIT(x, n) x &= ~(1U << (n));

namespace WinLibKernel {
	namespace Mem {
		class cr0 {
		public:
			static KIRQL wp_off() {
				KIRQL irql = KeRaiseIrqlToDpcLevel();
				UINT64 cr0 = __readcr0();
				CLR_BIT(cr0, 16);
				__writecr0(cr0);
				_disable();
				return irql;
			}

			static VOID wp_on(KIRQL irql) {
				UINT64 cr0 = __readcr0();
				SET_BIT(cr0, 16);
				_enable();
				__writecr0(cr0);
				KeLowerIrql(irql);
			}
		};
	}
}