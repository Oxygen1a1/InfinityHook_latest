#pragma once
#include <fltKernel.h>
/// <summary>
/// in this head file you can get 
///some windows kernel global var address or some system tools like bypass sign check and so on
///  author : oxygen
/// 
/// </summary>
namespace kstd {


	

#ifndef _WIN64
#define KDDEBUGGER_DATA_OFFSET 0x1068
#else
#define KDDEBUGGER_DATA_OFFSET 0x2080
#endif


	static const unsigned poolTag = 'sysi';
	class SysInfoManager {
	public:
		typedef struct _DBGKD_DEBUG_DATA_HEADER64 {
			LIST_ENTRY64 List;
			ULONG           OwnerTag;
			ULONG           Size;
		} DBGKD_DEBUG_DATA_HEADER64, * PDBGKD_DEBUG_DATA_HEADER64;
		typedef struct _KDDEBUGGER_DATA64 {

			DBGKD_DEBUG_DATA_HEADER64 Header;

			//
			// Base address of kernel image
			//

			ULONG64   KernBase;

			//
			// DbgBreakPointWithStatus is a function which takes an argument
			// and hits a breakpoint.  This field contains the address of the
			// breakpoint instruction.  When the debugger sees a breakpoint
			// at this address, it may retrieve the argument from the first
			// argument register, or on x86 the eax register.
			//

			ULONG64   BreakpointWithStatus;       // address of breakpoint

			//
			// Address of the saved context record during a bugcheck
			//
			// N.B. This is an automatic in KeBugcheckEx's frame, and
			// is only valid after a bugcheck.
			//

			ULONG64   SavedContext;

			//
			// help for walking stacks with user callbacks:
			//

			//
			// The address of the thread structure is provided in the
			// WAIT_STATE_CHANGE packet.  This is the offset from the base of
			// the thread structure to the pointer to the kernel stack frame
			// for the currently active usermode callback.
			//

			USHORT  ThCallbackStack;            // offset in thread data

			//
			// these values are offsets into that frame:
			//

			USHORT  NextCallback;               // saved pointer to next callback frame
			USHORT  FramePointer;               // saved frame pointer

			//
			// pad to a quad boundary
			//
			USHORT  PaeEnabled;

			//
			// Address of the kernel callout routine.
			//

			ULONG64   KiCallUserMode;             // kernel routine

			//
			// Address of the usermode entry point for callbacks.
			//

			ULONG64   KeUserCallbackDispatcher;   // address in ntdll


			//
			// Addresses of various kernel data structures and lists
			// that are of interest to the kernel debugger.
			//

			ULONG64   PsLoadedModuleList;
			ULONG64   PsActiveProcessHead;
			ULONG64   PspCidTable;

			ULONG64   ExpSystemResourcesList;
			ULONG64   ExpPagedPoolDescriptor;
			ULONG64   ExpNumberOfPagedPools;

			ULONG64   KeTimeIncrement;
			ULONG64   KeBugCheckCallbackListHead;
			ULONG64   KiBugcheckData;

			ULONG64   IopErrorLogListHead;

			ULONG64   ObpRootDirectoryObject;
			ULONG64   ObpTypeObjectType;

			ULONG64   MmSystemCacheStart;
			ULONG64   MmSystemCacheEnd;
			ULONG64   MmSystemCacheWs;

			ULONG64   MmPfnDatabase;
			ULONG64   MmSystemPtesStart;
			ULONG64   MmSystemPtesEnd;
			ULONG64   MmSubsectionBase;
			ULONG64   MmNumberOfPagingFiles;

			ULONG64   MmLowestPhysicalPage;
			ULONG64   MmHighestPhysicalPage;
			ULONG64   MmNumberOfPhysicalPages;

			ULONG64   MmMaximumNonPagedPoolInBytes;
			ULONG64   MmNonPagedSystemStart;
			ULONG64   MmNonPagedPoolStart;
			ULONG64   MmNonPagedPoolEnd;

			ULONG64   MmPagedPoolStart;
			ULONG64   MmPagedPoolEnd;
			ULONG64   MmPagedPoolInformation;
			ULONG64   MmPageSize;

			ULONG64   MmSizeOfPagedPoolInBytes;

			ULONG64   MmTotalCommitLimit;
			ULONG64   MmTotalCommittedPages;
			ULONG64   MmSharedCommit;
			ULONG64   MmDriverCommit;
			ULONG64   MmProcessCommit;
			ULONG64   MmPagedPoolCommit;
			ULONG64   MmExtendedCommit;

			ULONG64   MmZeroedPageListHead;
			ULONG64   MmFreePageListHead;
			ULONG64   MmStandbyPageListHead;
			ULONG64   MmModifiedPageListHead;
			ULONG64   MmModifiedNoWritePageListHead;
			ULONG64   MmAvailablePages;
			ULONG64   MmResidentAvailablePages;

			ULONG64   PoolTrackTable;
			ULONG64   NonPagedPoolDescriptor;

			ULONG64   MmHighestUserAddress;
			ULONG64   MmSystemRangeStart;
			ULONG64   MmUserProbeAddress;

			ULONG64   KdPrintCircularBuffer;
			ULONG64   KdPrintCircularBufferEnd;
			ULONG64   KdPrintWritePointer;
			ULONG64   KdPrintRolloverCount;

			ULONG64   MmLoadedUserImageList;

			// NT 5.1 Addition

			ULONG64   NtBuildLab;
			ULONG64   KiNormalSystemCall;

			// NT 5.0 hotfix addition

			ULONG64   KiProcessorBlock;
			ULONG64   MmUnloadedDrivers;
			ULONG64   MmLastUnloadedDriver;
			ULONG64   MmTriageActionTaken;
			ULONG64   MmSpecialPoolTag;
			ULONG64   KernelVerifier;
			ULONG64   MmVerifierData;
			ULONG64   MmAllocatedNonPagedPool;
			ULONG64   MmPeakCommitment;
			ULONG64   MmTotalCommitLimitMaximum;
			ULONG64   CmNtCSDVersion;

			// NT 5.1 Addition

			ULONG64   MmPhysicalMemoryBlock;
			ULONG64   MmSessionBase;
			ULONG64   MmSessionSize;
			ULONG64   MmSystemParentTablePage;

			// Server 2003 addition

			ULONG64   MmVirtualTranslationBase;

			USHORT    OffsetKThreadNextProcessor;
			USHORT    OffsetKThreadTeb;
			USHORT    OffsetKThreadKernelStack;
			USHORT    OffsetKThreadInitialStack;

			USHORT    OffsetKThreadApcProcess;
			USHORT    OffsetKThreadState;
			USHORT    OffsetKThreadBStore;
			USHORT    OffsetKThreadBStoreLimit;

			USHORT    SizeEProcess;
			USHORT    OffsetEprocessPeb;
			USHORT    OffsetEprocessParentCID;
			USHORT    OffsetEprocessDirectoryTableBase;

			USHORT    SizePrcb;
			USHORT    OffsetPrcbDpcRoutine;
			USHORT    OffsetPrcbCurrentThread;
			USHORT    OffsetPrcbMhz;

			USHORT    OffsetPrcbCpuType;
			USHORT    OffsetPrcbVendorString;
			USHORT    OffsetPrcbProcStateContext;
			USHORT    OffsetPrcbNumber;

			USHORT    SizeEThread;

			ULONG64   KdPrintCircularBufferPtr;
			ULONG64   KdPrintBufferSize;

			ULONG64   KeLoaderBlock;

			USHORT    SizePcr;
			USHORT    OffsetPcrSelfPcr;
			USHORT    OffsetPcrCurrentPrcb;
			USHORT    OffsetPcrContainedPrcb;

			USHORT    OffsetPcrInitialBStore;
			USHORT    OffsetPcrBStoreLimit;
			USHORT    OffsetPcrInitialStack;
			USHORT    OffsetPcrStackLimit;

			USHORT    OffsetPrcbPcrPage;
			USHORT    OffsetPrcbProcStateSpecialReg;
			USHORT    GdtR0Code;
			USHORT    GdtR0Data;

			USHORT    GdtR0Pcr;
			USHORT    GdtR3Code;
			USHORT    GdtR3Data;
			USHORT    GdtR3Teb;

			USHORT    GdtLdt;
			USHORT    GdtTss;
			USHORT    Gdt64R3CmCode;
			USHORT    Gdt64R3CmTeb;

			ULONG64   IopNumTriageDumpDataBlocks;
			ULONG64   IopTriageDumpDataBlocks;

			// Longhorn addition

			ULONG64   VfCrashDataBlock;
			ULONG64   MmBadPagesDetected;
			ULONG64   MmZeroedPageSingleBitErrorsDetected;

			// Windows 7 addition

			ULONG64   EtwpDebuggerData;
			USHORT    OffsetPrcbContext;

			// Windows 8 addition

			USHORT    OffsetPrcbMaxBreakpoints;
			USHORT    OffsetPrcbMaxWatchpoints;

			ULONG     OffsetKThreadStackLimit;
			ULONG     OffsetKThreadStackBase;
			ULONG     OffsetKThreadQueueListEntry;
			ULONG     OffsetEThreadIrpList;

			USHORT    OffsetPrcbIdleThread;
			USHORT    OffsetPrcbNormalDpcState;
			USHORT    OffsetPrcbDpcStack;
			USHORT    OffsetPrcbIsrStack;

			USHORT    SizeKDPC_STACK_FRAME;

			// Windows 8.1 Addition

			USHORT    OffsetKPriQueueThreadListHead;
			USHORT    OffsetKThreadWaitReason;

			// Windows 10 RS1 Addition

			USHORT    Padding;
			ULONG64   PteBase;

			// Windows 10 RS5 Addition

			ULONG64 RetpolineStubFunctionTable;
			ULONG RetpolineStubFunctionTableSize;
			ULONG RetpolineStubOffset;
			ULONG RetpolineStubSize;

		} KDDEBUGGER_DATA64, * PKDDEBUGGER_DATA64;


	public:
		static SysInfoManager* getInstance();
		static void destory();
		static void byPassSignCheck(PDRIVER_OBJECT drv);
	public:
		KDDEBUGGER_DATA64* getSysInfo() const { return	&__dumpHeader; }
		ULONG getBuildNumber();
	public:
		inline static SysInfoManager* __instance;
		inline static KDDEBUGGER_DATA64 __dumpHeader;
	};



	inline SysInfoManager* kstd::SysInfoManager::getInstance(){

		UNICODE_STRING u_func_name = RTL_CONSTANT_STRING(L"KeCapturePersistentThreadState");
		char* tmp = nullptr;

		do {
			if (__instance != nullptr) break;
			__instance = reinterpret_cast<SysInfoManager*>(ExAllocatePoolWithTag(NonPagedPool,
				sizeof SysInfoManager,
				poolTag));
		
			if(__instance==nullptr) break;

#define DUMP_BLOCK_SIZE 0X40000

			tmp = reinterpret_cast<char*>(ExAllocatePoolWithTag(NonPagedPool, DUMP_BLOCK_SIZE, 'sysI'));
			if (tmp == nullptr) {
				break;
			}
			CONTEXT context = { 0 };
			context.ContextFlags = CONTEXT_FULL;
			RtlCaptureContext(&context);
			
			auto func = reinterpret_cast<void(*)(CONTEXT*, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, void*)>(
				MmGetSystemRoutineAddress(&u_func_name));
			if (func == nullptr) break;

			func(&context, 0, 0, 0, 0, 0, 0, tmp);

			memcpy(&__dumpHeader, tmp + KDDEBUGGER_DATA_OFFSET, sizeof __dumpHeader);

			if (tmp) ExFreePool(tmp);
			return __instance;

		} while (false);


		if (__instance != nullptr) {
			ExFreePool(__instance);
			__instance = nullptr;
		}

		if (tmp) ExFreePool(tmp);
		
		return nullptr;
	}

	inline void SysInfoManager::destory()
	{
		if (__instance != nullptr) {
			ExFreePool(__instance);
		}
	}

	inline void SysInfoManager::byPassSignCheck(PDRIVER_OBJECT drv)
	{
		//STRUCT FOR WIN64
		typedef struct _LDR_DATA                         			// 24 elements, 0xE0 bytes (sizeof)
		{
			struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)
			struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)
			struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)
			VOID* DllBase;
			VOID* EntryPoint;
			ULONG32 SizeOfImage;
			UINT8 _PADDING0_[0x4];
			struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)
			struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)
			ULONG32 Flags;
		} LDR_DATA, * PLDR_DATA;
		PLDR_DATA ldr;
		ldr = (PLDR_DATA)(drv->DriverSection);
		ldr->Flags |= 0x20;
	}

	inline ULONG SysInfoManager::getBuildNumber()
	{
		RTL_OSVERSIONINFOW ver({});
		ULONG ret = 0xffffffff;

		if (NT_SUCCESS(RtlGetVersion(&ver))) {
			ret = ver.dwBuildNumber;
		}

		return ret;
	}




	
}