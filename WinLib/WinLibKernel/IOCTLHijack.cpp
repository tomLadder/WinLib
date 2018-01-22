#include "IOCTLHijack.h"

IOCTLHijack::IOCTLHijack(DRIVER_OBJECT *_victim) {
	this->victim = _victim;
}

BOOLEAN IOCTLHijack::isHijackable() {
	return this->victim->MajorFunction[IRP_MJ_DEVICE_CONTROL] != nullptr;
}