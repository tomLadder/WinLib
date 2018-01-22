#pragma once
#include "Detour.h"

class IOCTLHijack {
private:
	DRIVER_OBJECT *victim;
public:
	IOCTLHijack(DRIVER_OBJECT *_victim);
	BOOLEAN isHijackable();
	/* 
		==> TODO <== 
		Parameter: Callback (Called from new KernelThread)
						gets called if isHijackable gets TRUE
	*/
};