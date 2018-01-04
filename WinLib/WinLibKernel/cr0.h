#pragma once
#include <ntddk.h>
#include <intrin.h>

#define SET_BIT(x, n) x |= (1U << (n));
#define CLR_BIT(x, n) x &= ~(1U << (n));

namespace WinLibKernel {
	namespace Mem {
		class cr0 {
		public:
			static KIRQL wp_off();
			static VOID wp_on(KIRQL irql);
		};
	}
}