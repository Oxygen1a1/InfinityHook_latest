#pragma once
#ifndef _ETWHOOK_INIT_

#define _ETWHOOK_INIT_

#include <etwhook_base.hpp>


class EtwInitilizer :public EtwBase 
{
public:

	EtwInitilizer();

	~EtwInitilizer();

	NTSTATUS start_syscall_trace();
	NTSTATUS end_syscall_trace();

	/*打开这个 才会去HalPmcCounter函数执行*/
	NTSTATUS open_pmc_counter();


	unsigned char* get_EtwpMaxPmcCounter();

public:
	UINT_PTR* HalPrivateDispatchTable;
private:
	
	bool __is_open;
};

#endif