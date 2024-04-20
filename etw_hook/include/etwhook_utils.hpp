#pragma once
#ifndef _DM_UTILS_H_
#define _DM_UTILS_H_


NTSTATUS w2s(const wchar_t* src, char* dest, size_t destSize);
NTSTATUS s2w(const char* src, wchar_t* dest, size_t destSize);
void breakOnlyDebug();
auto find_module_base(const wchar_t* w_module_name, ULONG* size) -> void*;
bool _memcpy(PVOID address, PVOID target_address, ULONG length);
kstd::kwstring getModuleNameByPtr(PVOID p,PVOID* base=nullptr,size_t* size=nullptr);

#endif