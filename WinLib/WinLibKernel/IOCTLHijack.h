#pragma once
#include "Detour.h"

class IOCTLHijack {
private:
	DRIVER_OBJECT *victim;
public:
	IOCTLHijack(DRIVER_OBJECT *_victim);
	BOOLEAN isHijackable();
};