# 前言

ETW HOOK是一个经久不衰的话题了，本质上是微软的漏洞，再微软进行记录ETW时候系统调用的时候，被ETW相关组件拦截跑到记录的代码，因为涉及到的代码量实在太大，微软这里面老是会有一些函数指针的使用，从而可以把他替换成我们自己函数回调，而不会触发PG拦截系统调用(`无法拦截直接内核NtXXX`)。

## 早期的ETW HOOK实现概要

早期的ETW HOOK替换的一些HalPxx指针已经被PG监控

**https://github.com/everdox/InfinityHook**

到后来第二个版本的ETW，原理和EAC接管系统异常差不多，**这一版本的也是再ETW HOOK的必经之路上面修改函数指针**:

**原理是EAC通过修改`HalpStallCounter[0xE]`**的这个位置,以及`NtGlobalFlags`这个标志位。

HalpStallCounter[0xE] 函数原本是`HalpTscQueryCounterOrdered`,修改这个之后,一些异常(包括kernel mode)就会走到这从而被EAC接管;

下图是发生异常时候的调用栈

![image-20240119153903903](ETWHOOK%20WIN11%E5%85%BC%E5%AE%B9%E7%89%88.assets/image-20240119153903903.png)

从windbg可以看到,`EAC`修改了`HalpStallCounter`来进行接管异常

![77cd8914ea73abf464a9e0352ac255b0](ETWHOOK%20WIN11%E5%85%BC%E5%AE%B9%E7%89%88.assets/77cd8914ea73abf464a9e0352ac255b0.png)

## 可以兼容最新版 windows 的ETW HOOK

第二版的ETW Hook现在还可以用，但是用起来非常复杂，光是不同系统兼容、修栈就要耗费巨大精力。

因此这里参考国外的一个大佬文章，他提出了更新版本的ETW-HOOK，具体原理如下

WINDOWS的.data节一般是存放可以变的全局变量的，所谓的偷指针就是修改.data节区的指针。

而在这里，最好玩的是`HalPrivateDispatchTable`，这个是windows 的ntoskenl.exe为了方便使用HAL的导出函数，把他们存放在统一的地方。而HAL,用到的地方肯定很多，ETW 正是如此。

我们来看一下系统调用ETW的调用路径

![image-20240419102113440](ETWHOOK%20WIN11%E5%85%BC%E5%AE%B9%E7%89%88.assets/image-20240419102113440.png)

这里其实可以看到，`call rax`其实就是正常的系统调用，而再进入ETW系统调用之前，他把原始的系统调用存放在了栈上，这就导致我们拦截到ETW的时候，可以修改栈上的位置，来进行HOOK Syscall。

进入这个函数

![image-20240419102337381](ETWHOOK%20WIN11%E5%85%BC%E5%AE%B9%E7%89%88.assets/image-20240419102337381.png)

如果说之前无法定位，现在可以通过这个栈上面的`magic number`来定位syscall的地址，从而替换了。

继续跟到`EtwTraceSiloKernelEvent`里面，可以发现，无论参数怎么样，这个函数调用了`EtwpLogKernelEvent`

```C++
void __fastcall EtwTraceSiloKernelEvent(
        __int64 a1,
        __int64 a2,
        unsigned int a3,
        unsigned int a4,
        unsigned __int16 a5,
        int a6)
{
  unsigned __int64 v9; // rsi
  unsigned int v10; // ebx
  bool v11; // zf
  unsigned int v12; // ecx
  __int64 v13; // r8
  __int64 v14; // rcx
  __int64 v15; // rbx
  unsigned int v16; // edi
  __int64 v17; // rdx
  __int64 v18; // rcx
  unsigned int v19; // ecx

  v9 = a4;
  v10 = *(_DWORD *)(EtwpHostSiloState + 4224);
  while ( 1 )
  {
    v11 = !_BitScanForward(&v12, v10);
    if ( v11 )
      break;
    v10 &= v10 - 1;
    v13 = v12;
    v14 = 32i64 * v12 + EtwpHostSiloState + 4260;
    if ( v14 )
    {
      if ( ((unsigned int)v9 & *(_DWORD *)(v14 + 4 * (v9 >> 29)) & 0x1FFFFFFF) != 0 )
        EtwpLogKernelEvent(a2, EtwpHostSiloState, *(unsigned __int8 *)(EtwpHostSiloState + 2 * v13 + 4208), a3, a5, a6);
    }
  }
  if ( a1 )
  {
    v15 = *(_QWORD *)(*(_QWORD *)(a1 + 1272) + 864i64);
    if ( v15 )
    {
      v16 = *(_DWORD *)(v15 + 4224);
      while ( 1 )
      {
        v11 = !_BitScanForward(&v19, v16);
        if ( v11 )
          break;
        v17 = v19;
        v16 &= v16 - 1;
        v18 = 32i64 * v19 + v15 + 4260;
        if ( v18 && ((unsigned int)v9 & *(_DWORD *)(v18 + 4 * (v9 >> 29)) & 0x1FFFFFFF) != 0 )
          EtwpLogKernelEvent(a2, v15, *(unsigned __int8 *)(v15 + 2 * v17 + 4208), a3, a5, a6);
      }
    }
  }
}
```

而`EtwpLogKernelEvent`就是这次事件的主角，关键部分代码为

```C++
     else
      {
        if ( (v32 & 0x800) == 0 )
          goto LABEL_17;
        v50 = 0;
        if ( !*(_DWORD *)(*(_QWORD *)(v14 + 1000) + 8i64) )
          goto LABEL_17;
        while ( 1 )
        {
          v51 = *(_QWORD *)(v14 + 1000);
          if ( *(_WORD *)(v51 + 2i64 * v50 + 12) == a5 )
            break;
          if ( ++v50 >= *(_DWORD *)(v51 + 8) )
            goto LABEL_17;
        }
        LODWORD(Flags) = a6;
        TimeStamp = &v58;
        v34 = (char *)EtwpReserveWithPmcCounters(v14, a5);// 正常设置Etw trace kernel 并不会走到这个地方！！要进行ETW配置
```

事实上，如果正常设置了ETW Logger syscall，就会走到这。这个函数的关键部分如下

```C++
mcData = LoggerContext->PmcData;
  v8 = *(_DWORD *)(PmcData + 20);
  v9 = 8 * (unsigned __int8)v8 + 16;
  v10 = v9 + AuxSize;
  CurrentIrql = KeGetCurrentIrql();
  if ( CurrentIrql < 2u )
  {
    v12 = KeGetCurrentIrql();
    __writecr8(2ui64);
    if ( KiIrqlFlags )
    {
      if ( (KiIrqlFlags & 1) != 0 && v12 <= 0xFu )
      {
        SchedulerAssist = KeGetCurrentPrcb()->SchedulerAssist;
        *(_DWORD *)(SchedulerAssist + 20) |= (-1 << (v12 + 1)) & 4;
      }
    }
  }
  v14 = EtwpReserveTraceBuffer((unsigned int *)LoggerContext, v10, (__int64)BufferHandle, TimeStamp, Flags);
  v15 = v14;
  if ( v14 )
  {
    *(LARGE_INTEGER *)(v14 + 8) = *TimeStamp;
    *(_WORD *)(v14 + 4) = v10;
    *(_WORD *)(v14 + 6) = HookId;
    *(_DWORD *)v14 = (unsigned __int8)Flags | ((unsigned __int8)v8 << 8) | 0xC0110000;
    v21 = *(struct _HAL_PMC_COUNTERS **)(PmcData + 8i64 * (unsigned int)KeGetPcr()->Prcb.Number + 24);
    if ( v21 )
      HalPrivateDispatchTable.HalCollectPmcCounters(v21, (unsigned __int64 *)(v14 + 16));
    else
      memset((void *)(v14 + 16), 0, 8i64 * (unsigned __int8)v8);
```

这个地方`HalPrivateDispatchTable.HalCollectPmcCounters(v21, (unsigned __int64 *)(v14 + 16));`就是可以替换的，也就是我们要替换`HalPrivateDispatchTable`的`HalCollectPmcCounters`.从而可以正常地接管syscall而不触发PG。

# 具体实现

具体实现上其实很简单，就是调用`ZwTraceControl`开启配置`NT Kernel Logger`，这些代码都很简单，大概步骤是

1. 偷指针，替换
2. 配置Nt Kernel Logger，开启ETW
3. **最麻烦的一步，如何设置PMCCounter开启，从而走到EtwpReserveWithPmcCounters**
4. 栈查找定位Syscall Routine
5. 替换你想HOOK的系统调用

上述所有步骤基本再第一版的`etw hook`里面都有代码，除了第三步。

而参考文章[1]中，对于这部分的描述是`the code has been omitted from this article.`，因此只能根据他给的寥寥信息逆向。好在最终逆出来了。

如果正常开启ETW,可以发现，`EtwpReserveWithPmcCounters`无法进入。我们可以看一下相关的判断：

![image-20240420200101609](ETWHOOK%20WIN11%E5%85%BC%E5%AE%B9%E7%89%88.assets/image-20240420200101609.png)

因此需要设置的是相关的位。这个位设置需要用到`NtSetSystemInfomation`(需要自己逆向)。

具体需要逆向的是部分在`EtwSetPerformanceTraceInformation`函数中的如下部分

![image-20240420200338164](ETWHOOK%20WIN11%E5%85%BC%E5%AE%B9%E7%89%88.assets/image-20240420200338164-1713614621292-3.png)

`EtwpUpdatePmcCounters`这个函数是分配`PmcData`同时开启`flag`;

`EtwpUpdatePmcEvents`是设置开启哪些hookid，比如syscall就是`0xf33`。最后可以用如下代码设置PmcCounter

```C++
/*其实这个要调用ZwSetSystemInfomation，但是没有找到合适的文档化和文章，故只能手动逆向windows，最终得出结果*/
NTSTATUS EtwInitilizer::open_pmc_counter()
{
	auto status = STATUS_SUCCESS;
	auto pmc_count_info = (PEVENT_TRACE_PROFILE_COUNTER_INFORMATION)(nullptr);
	auto pmc_event_info=(PEVENT_TRACE_SYSTEM_EVENT_INFORMATION)(nullptr);
	constexpr auto syscall_hookid = 0xf33ul;



	if (!__is_open) return STATUS_FLT_NOT_INITIALIZED;

	do {

		/*获取ckcl_context的loggerid*/
		auto EtwpDebuggerData=reinterpret_cast<ULONG***>( \
			kstd::SysInfoManager::getInstance()->getSysInfo()->EtwpDebuggerData);
		
		if (!EtwpDebuggerData) {
			status = STATUS_NOT_SUPPORTED;
			LOG_ERROR("failed to get EtwpDebuggerData!\r\n");
		}
		
		/*这个可以参考第一版的ETW HOOK，这里简写了*/
		auto logger_id = EtwpDebuggerData[2][2][0];

		pmc_count_info = kalloc<EVENT_TRACE_PROFILE_COUNTER_INFORMATION>(NonPagedPool);
		if (!pmc_count_info) {
			LOG_ERROR("failed to alloc memory for pmc_count!\r\n");
			status = STATUS_MEMORY_NOT_ALLOCATED;
			break;
		}
		//先设置PMC Count 我们只关心一个hookid 那就是syscall的hookid 0xf33 profile source 随便设置
		pmc_count_info->EventTraceInformationClass = EventTraceProfileCounterListInformation;
		pmc_count_info->TraceHandle = ULongToHandle(logger_id)/*这个其实就是loggerid*/;
		pmc_count_info->ProfileSource[0] = 1;/*随便填写*/

		status=ZwSetSystemInformation(SystemPerformanceTraceInformation, pmc_count_info, sizeof EVENT_TRACE_PROFILE_COUNTER_INFORMATION);
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("failed to configure pmc counter,errcode=%x\r\n", status);
			break;
		}


		//然后设置PMC Event hookid只需要一个就行
		pmc_event_info = kalloc<EVENT_TRACE_SYSTEM_EVENT_INFORMATION>(NonPagedPool);
		if (!pmc_event_info) {
			LOG_ERROR("failed to alloc memory for pmc_event_info!\r\n");
			status = STATUS_MEMORY_NOT_ALLOCATED;
			break;
		}

		pmc_event_info->EventTraceInformationClass = EventTraceProfileEventListInformation;
		pmc_event_info->TraceHandle = ULongToHandle(logger_id);
		pmc_event_info->HookId[0] = syscall_hookid;/*必须0xf33*/


		status = ZwSetSystemInformation(SystemPerformanceTraceInformation, pmc_event_info, sizeof EVENT_TRACE_SYSTEM_EVENT_INFORMATION);
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("failed to configure pmc event,errcode=%x\r\n", status);
			break;
		}

		
	} while (false);

	//clean up
	if (pmc_count_info) ExFreePool(pmc_count_info);
	if (pmc_event_info) ExFreePool(pmc_event_info);

	return status;
}
```

**这里还有个坑**，就是`EtwpUpdatePmcCounters`这个部分的代码如下

```C++
__int64 __fastcall EtwpUpdatePmcCounters(
        _WMI_LOGGER_CONTEXT *wmi_context,
        _KPROFILE_SOURCE *profile_array,
        unsigned int count)
{
  unsigned int v6; // r12d
  __int64 result; // rax
  _ETW_PMC_SUPPORT *PmcData; // r14
  __int64 i; // r8
  unsigned int v10; // r15d
  unsigned int cpu_idx; // edi
  __int64 j; // rsi
  signed __int32 unk_struct[22]; // [rsp+0h] [rbp-58h] BYREF

  v6 = KeNumberProcessors_0;
  if ( !count || count > EtwpMaxPmcCounter || wmi_context->PoolType == 1 )// 不能是PagedPool
    return 0xC000000Di64;
  if ( wmi_context->PmcData || (result = EtwpAllocatePmcData((__int64)wmi_context), !(_DWORD)result) )// 分配成功
  {
```

`count > EtwpMaxPmcCounter`这一个必须成立，我的虚拟机这个是1，也就是必须得强制改动这个值。

但是观察，我的物理机又是>1，这个全局变量比较难定位。暂时没有处理。

## 效果

最后效果如下

![image-20240420213841614](ETWHOOK%20WIN11%E5%85%BC%E5%AE%B9%E7%89%88.assets/image-20240420213841614.png)

# 参考

[1] Fun With Another PG-Compliant Hook https://revers.engineering/fun-with-pg-compliant-hook/

[2] 仿照EAC的全局异常Hook https://bbs.kanxue.com/thread-278475.htm