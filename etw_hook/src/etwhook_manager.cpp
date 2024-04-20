#include <etwhook_manager.hpp>
#include <kstl/ksystem_info.hpp>
#include <kstl/kpe_parse.hpp>
#include <etwhook_utils.hpp>
#include <intrin.h>


EtwHookManager* EtwHookManager::__instance;

void(* EtwHookManager::__orghalcollectpmccounters)(void*, unsigned long long);

EtwHookManager* EtwHookManager::get_instance()
{
	if (!__instance) __instance = new EtwHookManager;
	return __instance;
}

NTSTATUS EtwHookManager::init()
{
	auto status = STATUS_UNSUCCESSFUL;

	/*检查是否分配单例的内存了*/
	if (!__instance) return STATUS_MEMORY_NOT_ALLOCATED;

	/*这种方法不支持win7*/
	auto info_instance=kstd::SysInfoManager::getInstance();
	if (info_instance == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
	if (info_instance->getBuildNumber() <= 7601) 
	{
		LOG_ERROR("current os version is not supported!\r\n");
		return STATUS_NOT_SUPPORTED;
	}


	do {
		status = this->__initilizer.start_syscall_trace();
		if (!NT_SUCCESS(status)) break;

		/**/
		status = this->__initilizer.open_pmc_counter();
		if(!NT_SUCCESS(status)) break;

		if (this->__initilizer.HalPrivateDispatchTable == nullptr) {
			status = STATUS_UNSUCCESSFUL;
			LOG_ERROR("failed to get HalPrivateDispatchTable address!\r\n");
			break;
		}

		_disable();
		/*swap*/
		__orghalcollectpmccounters = reinterpret_cast<void(*)(void*, unsigned long long)> \
			(this->__initilizer.HalPrivateDispatchTable[__halcollectpmccounters_idx]);
	
		this->__initilizer.HalPrivateDispatchTable[__halcollectpmccounters_idx] = \
			reinterpret_cast<ULONG_PTR>(hk_halcollectpmccounters);

		_enable();


	} while (false);


	//clean up

	//if fail

	//if suc

	return status;
}

NTSTATUS EtwHookManager::destory()
{
	auto status = STATUS_UNSUCCESSFUL;

	if (!__instance) return STATUS_MEMORY_NOT_ALLOCATED;

	do {

		delete __instance;

		__instance = nullptr;

		status = STATUS_SUCCESS;

	} while (false);
	
	return status;
}

NTSTATUS EtwHookManager::add_hook(void* org_syscall, void* detour_routine)
{
	if (!__instance) return STATUS_FLT_NOT_INITIALIZED;

	auto suc=__hookmaps.insert({ org_syscall,detour_routine });

	return suc ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

}

NTSTATUS EtwHookManager::remove_hook(void* org_syscall)
{
	if(!__instance) return STATUS_FLT_NOT_INITIALIZED;
	
	auto need_delete = __hookmaps.find({ org_syscall,nullptr });

	if (!need_delete) return STATUS_NOT_FOUND;

	__hookmaps.remove(need_delete);

	return STATUS_SUCCESS;
}

void EtwHookManager::hk_halcollectpmccounters(void* ctx, unsigned long long trace_buffer_end)
{
	//LOG_INFO("filter success! arg1->%llx,arg2->%llx\r\n", ctx, trace_buffer_end);
	
	EtwHookManager::get_instance()->stack_trace_to_syscall();
	
	return __orghalcollectpmccounters(ctx, trace_buffer_end);
}



//sys_call_etw_entry
//48 83 EC 50                   sub     rsp, 50h
//48 89 4C 24 20                mov[rsp + 20h], rcx
//48 89 54 24 28                mov[rsp + 28h], rdx
//4C 89 44 24 30                mov[rsp + 30h], r8
//4C 89 4C 24 38                mov[rsp + 38h], r9
//4C 89 54 24 40                mov[rsp + 40h], r10
//49 8B CA                      mov     rcx, r10
//E8 54 A5 19 00                call    PerfInfoLogSysCallEntry
//48 8B 4C 24 20                mov     rcx, [rsp + 20h]
//48 8B 54 24 28                mov     rdx, [rsp + 28h]
//4C 8B 44 24 30                mov     r8, [rsp + 30h]
//4C 8B 4C 24 38                mov     r9, [rsp + 38h]
//4C 8B 54 24 40                mov     r10, [rsp + 40h]
//48 83 C4 50                   add     rsp, 50h
//49 8B C2                      mov     rax, r10
//FF D0                         call    rax
/*寻找方法是
1.先确定是不是有魔数字(看起来好像是不需要？因为这种方法只有系统调用会进入filter 函数)
2.确定KiSyscall64的起始和结束地址
3.栈遍历，遍历到之后，是否是位于起始和结束地址 如果是，说明栈目前位于

rsp->KiSyscall64.call    PerfInfoLogSysCallEntry
rsp+0x48==TargetSystemCall

*/

EtwHookManager::EtwHookManager() : __hookmaps() {

	__nt_img = find_module_base(L"ntoskrnl.exe", &__nt_size);

	kstd::ParsePE ntos(__nt_img, __nt_size);


	/*注意，这个方法并不严谨！没有直接readmsr IA32_LSTAR 然后使用反汇编引擎解析严谨*/
	//KiSystemServiceRepeat:
	//	4C 8D 15 85 6F 9F 00          lea     r10, KeServiceDescriptorTable
	//	4C 8D 1D FE 20 8F 00          lea     r11, KeServiceDescriptorTableShadow
	//	F7 43 78 80 00 00 00          test    dword ptr[rbx + 78h], 80h; GuiThread
	/*KiSystemServiceRepeat一定位于KiSystemCall64之中，这个直接进行特征码搜索*/

	__KiSystemServiceRepeat = ntos.patternFindSections((unsigned long long)__nt_img, \
		"\x4c\x8d\x15\x00\x00\x00\x00\x4c\x8d\x1d\x00\x00\x00\x00\xf7\x43", \
		"xxx????xxx????xx", ".text");

	/*初始化二叉树*/
	__hookmaps.init();
}

EtwHookManager::~EtwHookManager()
{
	/*关闭etw trace*/
	__initilizer.end_syscall_trace();

	/*恢复HalPrivateHook*/
	_disable();
	this->__initilizer.HalPrivateDispatchTable[__halcollectpmccounters_idx] = \
		reinterpret_cast<ULONG_PTR>(__orghalcollectpmccounters);
	_enable();

	/*销毁HookMap*/
	__hookmaps.destory();

}

void EtwHookManager::stack_trace_to_syscall()
{
	auto stack_max=(PVOID*)__readgsqword(0x1A8);
	auto cur_stack = (PVOID*)_AddressOfReturnAddress();
	constexpr auto magic1 = 0x501802ul;
	constexpr auto magic2 = 0xf33ul;

	do {

		if (!__KiSystemServiceRepeat) {
			LOG_ERROR("failed to find KiSystemServiceRepeat\r\n");
			break;
		}

		if (!__nt_img) {
			LOG_ERROR("failed to find ntoskrnl.exe");
			break;
		}

		/*
		cur_stack->	xxx
					...
					magic_number
					...
					syscall   <-先从上面开始遍历
					stack_max
		*/

		/*开始遍历堆栈*/

		for (;cur_stack<stack_max;cur_stack++) {

			auto stack_as_ushort = reinterpret_cast<PUSHORT>(cur_stack);

			if(*stack_as_ushort != magic2) continue;

			cur_stack++;

			auto stack_as_ulong = reinterpret_cast<PULONG>(cur_stack);

			if(*stack_as_ulong != magic1) continue;

			/*开始遍历*/
			for (; cur_stack < stack_max; cur_stack++) {
				
				if ((ULONG_PTR)*cur_stack >= (ULONG_PTR)PAGE_ALIGN(__KiSystemServiceRepeat) \
					&&
					(ULONG_PTR)*cur_stack <= (ULONG_PTR)PAGE_ALIGN(__KiSystemServiceRepeat + PAGE_SIZE * 2)
					) {
					//find 注意!!! 这个cur_stck不能100%保证是syscall，因为sys_exit的时候也会走到这
					record_syscall(cur_stack);

					break;
				}

			}

			break;

		}


	} while (false);
	
	//clean up

}

void EtwHookManager::record_syscall(void** call_routine)
{
	//LOG_INFO("syscalled->%p\r\n", call_routine[9]);


	auto hk_map=__hookmaps.find({ call_routine[9],nullptr });

	if (!hk_map) return;

	if (hk_map->detour_func) {

		call_routine[9] = hk_map->detour_func;
	}

}
