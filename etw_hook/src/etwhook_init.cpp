#include <etwhook_init.hpp>
#include <kstl/ksystem_info.hpp>

#pragma warning(disable : 4201)

#define EtwpStartTrace		1
#define EtwpStopTrace		2
#define EtwpQueryTrace		3
#define EtwpUpdateTrace		4
#define EtwpFlushTrace		5

#define WNODE_FLAG_TRACED_GUID			0x00020000  // denotes a trace
#define EVENT_TRACE_BUFFERING_MODE      0x00000400  // Buffering mode only
#define EVENT_TRACE_FLAG_SYSTEMCALL     0x00000080  // system calls

typedef struct _WNODE_HEADER
{
	ULONG BufferSize;        // Size of entire buffer inclusive of this ULONG
	ULONG ProviderId;    // Provider Id of driver returning this buffer
	union
	{
		ULONG64 HistoricalContext;  // Logger use
		struct
		{
			ULONG Version;           // Reserved
			ULONG Linkage;           // Linkage field reserved for WMI
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	union
	{
		ULONG CountLost;         // Reserved
		HANDLE KernelHandle;     // Kernel handle for data block
		LARGE_INTEGER TimeStamp; // Timestamp as returned in units of 100ns
								 // since 1/1/1601
	} DUMMYUNIONNAME2;
	GUID Guid;                  // Guid for data block returned with results
	ULONG ClientContext;
	ULONG Flags;             // Flags, see below
} WNODE_HEADER, * PWNODE_HEADER;

typedef struct _EVENT_TRACE_PROPERTIES {
	WNODE_HEADER	Wnode;
	ULONG			BufferSize;
	ULONG			MinimumBuffers;
	ULONG			MaximumBuffers;
	ULONG			MaximumFileSize;
	ULONG			LogFileMode;
	ULONG			FlushTimer;
	ULONG			EnableFlags;
	LONG			AgeLimit;
	ULONG			NumberOfBuffers;
	ULONG			FreeBuffers;
	ULONG			EventsLost;
	ULONG			BuffersWritten;
	ULONG			LogBuffersLost;
	ULONG			RealTimeBuffersLost;
	HANDLE			LoggerThreadId;
	ULONG			LogFileNameOffset;
	ULONG			LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, * PEVENT_TRACE_PROPERTIES;

/* 54dea73a-ed1f-42a4-af713e63d056f174 */
const GUID CkclSessionGuid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

/*这个是Nt kernel Logger 的 guid 其实设置谁都一样！*/
const GUID session_guid = { 0x9E814AAD, 0x3204, 0x11D2, { 0x9A, 0x82, 0x0, 0x60, 0x8, 0xA8, 0x69, 0x39 } };

typedef struct _CKCL_TRACE_PROPERIES : EVENT_TRACE_PROPERTIES
{
	ULONG64					Unknown[3];
	UNICODE_STRING			ProviderName;
} CKCL_TRACE_PROPERTIES, * PCKCL_TRACE_PROPERTIES;

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwTraceControl(
	_In_ ULONG FunctionCode,
	_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
	_In_ ULONG InBufferLen,
	_Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
	_In_ ULONG OutBufferLen,
	_Out_ PULONG ReturnLength
);

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetSystemInformation(ULONG info_class,void* buf,ULONG length);

typedef enum _EVENT_TRACE_INFORMATION_CLASS {
	EventTraceKernelVersionInformation,
	EventTraceGroupMaskInformation,
	EventTracePerformanceInformation,
	EventTraceTimeProfileInformation,
	EventTraceSessionSecurityInformation,
	EventTraceSpinlockInformation,
	EventTraceStackTracingInformation,
	EventTraceExecutiveResourceInformation,
	EventTraceHeapTracingInformation,
	EventTraceHeapSummaryTracingInformation,
	EventTracePoolTagFilterInformation,
	EventTracePebsTracingInformation,
	EventTraceProfileConfigInformation,
	EventTraceProfileSourceListInformation,
	EventTraceProfileEventListInformation,
	EventTraceProfileCounterListInformation,
	EventTraceStackCachingInformation,
	EventTraceObjectTypeFilterInformation,
	MaxEventTraceInfoClass
} EVENT_TRACE_INFORMATION_CLASS;

typedef struct _EVENT_TRACE_PROFILE_COUNTER_INFORMATION
{
	EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
	HANDLE TraceHandle;
	ULONG ProfileSource[1];
} EVENT_TRACE_PROFILE_COUNTER_INFORMATION, * PEVENT_TRACE_PROFILE_COUNTER_INFORMATION;

typedef struct _EVENT_TRACE_SYSTEM_EVENT_INFORMATION
{
	EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
	HANDLE TraceHandle;
	ULONG HookId[1];
} EVENT_TRACE_SYSTEM_EVENT_INFORMATION, * PEVENT_TRACE_SYSTEM_EVENT_INFORMATION;

const ULONG SystemPerformanceTraceInformation = 31;



EtwInitilizer::EtwInitilizer() : __is_open(false)
{
	
	UNICODE_STRING func_name = {};

	RtlInitUnicodeString(&func_name, L"HalPrivateDispatchTable");
	HalPrivateDispatchTable = reinterpret_cast<UINT_PTR*>(MmGetSystemRoutineAddress(&func_name));
	
	if (HalPrivateDispatchTable == nullptr) {
		LOG_ERROR("failed to get HalPrivateDispatchTable");
	}

}


EtwInitilizer::~EtwInitilizer()
{
	/*如果开启着，那么需要关闭*/
	if (__is_open) end_syscall_trace();
}

NTSTATUS EtwInitilizer::start_syscall_trace()
{
	auto status = STATUS_UNSUCCESSFUL;
	auto ckcl_property = (PCKCL_TRACE_PROPERTIES)(nullptr);
	auto returnlen = 0ul;

	do {

		ckcl_property = kalloc<CKCL_TRACE_PROPERTIES>(NonPagedPool,PAGE_SIZE);
		if (!ckcl_property) {
			LOG_ERROR("failed to alloc memory for etw property!\r\n");
			status = STATUS_MEMORY_NOT_ALLOCATED;
			break;
		}

		memset(ckcl_property, 0, PAGE_SIZE);
		ckcl_property->Wnode.BufferSize = PAGE_SIZE;
		ckcl_property->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		//ckcl_property->ProviderName = RTL_CONSTANT_STRING(L"NT Kernel Logger");
		//ckcl_property->Wnode.Guid = session_guid;
		ckcl_property->ProviderName = RTL_CONSTANT_STRING(L"Circular Kernel Context Logger");
		ckcl_property->Wnode.Guid = CkclSessionGuid;
		ckcl_property->Wnode.ClientContext = 1;
		ckcl_property->BufferSize = sizeof(ULONG);
		ckcl_property->MinimumBuffers = ckcl_property->MaximumBuffers = 2;
		ckcl_property->LogFileMode = EVENT_TRACE_BUFFERING_MODE;
		
		//enable kernel logger etw trace
		status = ZwTraceControl(EtwpStartTrace, ckcl_property, PAGE_SIZE, ckcl_property, PAGE_SIZE, &returnlen);
		
		//sometimes may return value is STATUS_OBJECT_NAME_COLLISION
		if (!NT_SUCCESS(status) && status!= STATUS_OBJECT_NAME_COLLISION) {
			LOG_ERROR("failed to enable kernel loggger etw trace,errcode=%x\r\n", status);
			break;
		}

		//start syscall etw
		ckcl_property->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;

		status=  ZwTraceControl(EtwpUpdateTrace, ckcl_property, PAGE_SIZE, ckcl_property, PAGE_SIZE, &returnlen);
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("failed to enable syscall etw,errcode=%x\r\n", status);
			end_syscall_trace();
			break;
		}

	} while (false);

	//clean up

	if (ckcl_property) ExFreePool(ckcl_property);
	
	//if fail
	//to do
	
	//if success clean
	if (NT_SUCCESS(status)) __is_open = true;
	
	return status;
}

NTSTATUS EtwInitilizer::end_syscall_trace()
{
	auto status = STATUS_UNSUCCESSFUL;
	auto ckcl_property = (PCKCL_TRACE_PROPERTIES)(nullptr);
	auto returnlen = 0ul;

	do {

		ckcl_property = kalloc<CKCL_TRACE_PROPERTIES>(NonPagedPool, PAGE_SIZE);
		if (!ckcl_property) {
			LOG_ERROR("failed to alloc memory for etw property!\r\n");
			status = STATUS_MEMORY_NOT_ALLOCATED;
			break;
		}

		

		memset(ckcl_property, 0, PAGE_SIZE);
		ckcl_property->Wnode.BufferSize = PAGE_SIZE;
		ckcl_property->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		//ckcl_property->ProviderName = RTL_CONSTANT_STRING(L"NT Kernel Logger");
		//ckcl_property->Wnode.Guid = session_guid;
		ckcl_property->ProviderName = RTL_CONSTANT_STRING(L"Circular Kernel Context Logger");
		ckcl_property->Wnode.Guid = CkclSessionGuid;
		ckcl_property->Wnode.ClientContext = 1;
		ckcl_property->BufferSize = sizeof(ULONG);
		ckcl_property->MinimumBuffers = ckcl_property->MaximumBuffers = 2;
		ckcl_property->LogFileMode = EVENT_TRACE_BUFFERING_MODE;

		//enable kernel logger etw trace
		status = ZwTraceControl(EtwpStopTrace, ckcl_property, PAGE_SIZE, ckcl_property, PAGE_SIZE, &returnlen);

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("failed to stop kernel loggger etw trace,errcode=%x\r\n", status);
			break;
		}


	} while (false);

	//clean up
	if (ckcl_property) ExFreePool(ckcl_property);
	
	if (NT_SUCCESS(status)) __is_open = false;

	return status;
}

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

#pragma warning(default : 4201)