#pragma once
#include <ntddk.h>

void* __cdecl operator new(size_t size, POOL_TYPE type, ULONG tag = 0);
void __cdecl operator delete(void* p, size_t);

void* __cdecl operator new(size_t size, POOL_TYPE type, ULONG tag) {
	return ExAllocatePoolWithTag(type, size, tag);
}
void __cdecl operator delete(void* p, size_t) {
	ExFreePool(p);
}