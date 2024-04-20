#include <refs.hpp>
#include <etwhook_utils.hpp>

void breakOnlyDebug() {

	if (!*KdDebuggerNotPresent) __debugbreak();

}

//sometimes there will occurs a bsod!?
kstd::kwstring getModuleNameByPtr(PVOID p,PVOID* base,size_t* size) {
	kstd::kwstring find_name{L"unknow module"};
	ULONG needSize = 0;
	ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &needSize);
	needSize += PAGE_SIZE;
	wchar_t* wstr = nullptr;

	const auto info = reinterpret_cast<SYSTEM_MODULE_INFORMATION*>(ExAllocatePoolWithTag(NonPagedPool, needSize, 'temp'));
	if (!MmIsAddressValid(info)) {
		LOG_ERROR("failed to alloa memory for sys infomation!\r\n");
		return find_name;
	}

	wstr = reinterpret_cast<wchar_t*>(ExAllocatePoolWithTag(NonPagedPool, 512*2, 'temp'));
	if (!MmIsAddressValid(wstr)) {
		LOG_ERROR("failed to alloa memory for str\r\n");
		return find_name;
	}

	do {

		if (!NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, info, needSize, &needSize))) {
			LOG_ERROR("failed to get system info!\r\n");
			break;
		}

		for (size_t i = 0; i < info->Count; i++) {
			SYSTEM_MODULE_ENTRY* module_entry = &(info->Module[i]);
		
			if ((ULONG_PTR)module_entry->BaseAddress <= (ULONG_PTR)(p) &&
				(UINT_PTR)module_entry->BaseAddress + module_entry->Size >= (ULONG_PTR)(p)) {
				

				s2w(module_entry->Name, wstr, 512);
				find_name = wstr;

				if (MmIsAddressValid(size)) *size = module_entry->Size;
				if (MmIsAddressValid(base)) *base = module_entry->BaseAddress;

				break;
			}
		}

	} while (false);

	//clean up
	if(MmIsAddressValid(info))
		ExFreePool(info);
	if (MmIsAddressValid(wstr))
		ExFreePool(wstr);
	return find_name;
}

NTSTATUS w2s(const wchar_t* src, char* dest, size_t destSize) {

	if (!src || !dest || destSize == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	size_t i = 0;
	while (src[i] != L'\0' && i < destSize - 1)
	{
		if (src[i] <= 0x7F) 
		{
			dest[i] = (char)src[i];
		}
		else
		{
			
			dest[i] = '?';
		}
		++i;
	}

	dest[i] = '\0';
	return STATUS_SUCCESS;
}

NTSTATUS s2w(const char* src, wchar_t* dest, size_t destSize) {


	if (!src || !dest || destSize == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	size_t i = 0;
	while (src[i] != '\0' && i < destSize - 1)
	{
		if (src[i] >= 0) 
		{
			dest[i] = (wchar_t)src[i];
		}
		else
		{
			
			dest[i] = L'?';
		}
		++i;
	}

	dest[i] = L'\0';

	return STATUS_SUCCESS;
}

auto find_module_base(const wchar_t* w_module_name, ULONG* size) -> void* {
	ULONG needSize = 0;
	ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &needSize);
	needSize *= 2;
	void* findBase = nullptr;
	char module_name[256] = {};

	w2s(w_module_name, module_name, sizeof module_name);

	auto info = reinterpret_cast<SYSTEM_MODULE_INFORMATION*>(
		ExAllocatePoolWithTag(NonPagedPool, needSize, 'temp'));

	if (info == nullptr) {
		return nullptr;
	}

	do {

		if (!NT_SUCCESS(
			ZwQuerySystemInformation(SystemModuleInformation, info, needSize, &needSize))) {
			break;

		}

		for (size_t i = 0; i < info->Count; i++) {
			SYSTEM_MODULE_ENTRY* module_entry = &info->Module[i];
			char* last_slash = strrchr(module_entry->Name, '\\');
			if (last_slash != nullptr) {
				last_slash++; // Skip the slash
			}
			else {
				last_slash = module_entry->Name;
			}
			
			if (_strnicmp(last_slash, module_name,strlen(module_name)) ==0/*ingore char senstive*/) {
				findBase = module_entry->BaseAddress;
				if (MmIsAddressValid(size)) *size = module_entry->Size;
				break;
			}
		}

	} while (false);

	//clean up
	if(MmIsAddressValid(info))
		ExFreePool(info);
	return findBase;
}

//Force copy across pages 
bool _memcpy(PVOID address, PVOID target_address, ULONG length)
{
	
	auto skipPhyPages = ((((UINT_PTR)(address)+length) >> PAGE_SHIFT) - ((UINT_PTR)address >> PAGE_SHIFT));

	if (!skipPhyPages) {
		bool result = false;
		PHYSICAL_ADDRESS physicial_address;
		physicial_address = MmGetPhysicalAddress(address);
		if (physicial_address.QuadPart)
		{
			PVOID maped_mem = MmMapIoSpace(physicial_address, length, MmNonCached);
			if (maped_mem)
			{
				memcpy(maped_mem, target_address, length);
				MmUnmapIoSpace(maped_mem, length);
				result = true;
			}
		}
		return result;
	}
	else {// 0x200 0x2900 3100 800 1000 
		auto firstPageCopy = PAGE_SIZE - (UINT_PTR)address & 0xfff;
		
		for (int i = 0; i <= skipPhyPages; i++) {
			if (i == 0) {
				PHYSICAL_ADDRESS physicial_address;
				physicial_address = MmGetPhysicalAddress(address);
				if (physicial_address.QuadPart)
				{
					PUCHAR maped_mem = (PUCHAR)MmMapIoSpace(physicial_address, firstPageCopy, MmNonCached);
					if (maped_mem)
					{
						memcpy(maped_mem, target_address, firstPageCopy);
						MmUnmapIoSpace(maped_mem, firstPageCopy);
					}
				}
				else return false;
			}
			else if (i == skipPhyPages) {
				auto lastPageCopy = length - PAGE_SIZE * (i - 1) - firstPageCopy;

				PHYSICAL_ADDRESS physicial_address;
				physicial_address = MmGetPhysicalAddress((PVOID)((UINT_PTR)(PAGE_ALIGN(address)) + PAGE_SIZE * i));
				if (physicial_address.QuadPart)
				{
					PUCHAR maped_mem = (PUCHAR)MmMapIoSpace(physicial_address, lastPageCopy, MmNonCached);
					if (maped_mem)
					{
						memcpy(maped_mem,
							(PUCHAR)target_address + firstPageCopy + (i - 1) * PAGE_SIZE, lastPageCopy);
						MmUnmapIoSpace(maped_mem, lastPageCopy);
					}
				}
				else return false;

			}
			else {
				PHYSICAL_ADDRESS physicial_address;
				physicial_address = MmGetPhysicalAddress((PVOID)((UINT_PTR)(PAGE_ALIGN(address)) + PAGE_SIZE * i));
				if (physicial_address.QuadPart)
				{
					PUCHAR maped_mem = (PUCHAR)MmMapIoSpace(physicial_address, PAGE_SIZE, MmNonCached);
					if (maped_mem)
					{
						memcpy(maped_mem,
							(PUCHAR)target_address + firstPageCopy + (i - 1) * PAGE_SIZE, PAGE_SIZE);
						MmUnmapIoSpace(maped_mem, PAGE_SIZE);
					}
				}
				else return false;

			}
		}
	}

	return true;
}


