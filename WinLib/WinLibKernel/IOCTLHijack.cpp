#include "IOCTLHijack.h"

IOCTLHijack::IOCTLHijack(DRIVER_OBJECT *_victim, CHAR _idx, IOCTLCallback _callback) {
	this->idx = _idx;
	this->callback = _callback;
	this->victim = _victim;
}

BOOLEAN IOCTLHijack::isHijackable() {
	return this->victim->MajorFunction[IRP_MJ_DEVICE_CONTROL] != nullptr;
}

BOOLEAN IOCTLHijack::watch() {
	HANDLE threadHandle = NULL;
	CLIENT_ID clientID = { 0 };
	OBJECT_ATTRIBUTES obAttr = { 0 };
	PVOID pThread = NULL;
	OBJECT_HANDLE_INFORMATION handleInfo = { 0 };

	union compilerHack {
		VOID (*func)(IOCTLHijack* this_ptr);
		PVOID addr;
	};

	compilerHack chack = { &IOCTLHijack::WatcherThread };

	InitializeObjectAttributes(&obAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	auto status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, &obAttr, NULL, &clientID, (PKSTART_ROUTINE)chack.addr, this);

	if (!NT_SUCCESS(status)) {
		return FALSE;
	}

	status = ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &pThread, &handleInfo);

	if (NT_SUCCESS(status)) {
		KeWaitForSingleObject(pThread, Executive, KernelMode, TRUE, NULL);
	}

	if (pThread) {
		ObDereferenceObject(pThread);
	}

	return TRUE;
}

VOID IOCTLHijack::WatcherThread(IOCTLHijack* obj) {
	UNREFERENCED_PARAMETER(obj);

	int i = 0;

	while (TRUE) {
		i++;
		PRINT("=> Hello From WatcherThread");

		if (i == 10)
			break;

		KeDelayExecutionThread(KernelMode, FALSE,(PLARGE_INTEGER) SECOND);
	}
}