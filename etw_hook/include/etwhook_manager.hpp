#pragma once
#include <refs.hpp>
#include <etwhook_base.hpp>
#include <etwhook_init.hpp>
#include <kstl/kavl.hpp>

class EtwHookManager  : public EtwBase
{
private:
	struct HookMap {
		void* org_func;
		void* detour_func;

		bool operator==(const HookMap& rhs) const { return this->org_func == rhs.org_func; }
		bool operator< (const HookMap& rhs) const { return this->org_func < rhs.org_func; }
		bool operator> (const HookMap& rhs) const { return this->org_func > rhs.org_func; }
	};

public:
	//单例
	static EtwHookManager* get_instance();

	NTSTATUS init();

	NTSTATUS destory();

	NTSTATUS add_hook(void* org_syscall,void* detour_routine);

	NTSTATUS remove_hook(void* org_syscall);

private:

	EtwHookManager();

	~EtwHookManager();

	static void hk_halcollectpmccounters(void* ctx, unsigned long long trace_buffer_end);

	void stack_trace_to_syscall();

	void record_syscall(void** call_routine);

private:
	
	kstd::kavl<HookMap> __hookmaps;

	EtwInitilizer __initilizer;

	static EtwHookManager* __instance;

	static void(*__orghalcollectpmccounters)(void*, unsigned long long);

	const ULONG  __halcollectpmccounters_idx = 73;

	void* __nt_img;
	ULONG __nt_size;
	ULONG_PTR __KiSystemServiceRepeat;


};