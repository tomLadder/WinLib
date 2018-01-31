#pragma once
#include "Detour.h"
#include "Debug.h"

#define SECOND	10000000

typedef NTSTATUS(*FUNC_IRP)(PDEVICE_OBJECT DriverObject, PIRP Irp);
typedef VOID(*IOCTLCallback)(FUNC_IRP func);

class IOCTLHijack {
private:
	DRIVER_OBJECT * victim;
	IOCTLCallback callback;
	CHAR idx;
public:
	IOCTLHijack(DRIVER_OBJECT *_victim, CHAR _idx, IOCTLCallback _callback);
	BOOLEAN isHijackable();

	BOOLEAN watch();
	/*
		==> TODO <==
		Parameter: Callback (Called from new KernelThread)
						gets called if isHijackable gets TRUE
	*/
	static VOID WatcherThread(IOCTLHijack* this_ptr);
};