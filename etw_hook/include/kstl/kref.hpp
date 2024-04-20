#pragma once

#include <fltKernel.h>

/// <summary>
/// author:oxygen
/// 更方便的通过 tid pid hProces hThread引用对象 并且不用解引用,同时可以ScopeAttach
/// </summary>
namespace kstd {
	class KScopeRefByProcessByHandle {
	public:
		void* get() const { return __process; }
		NTSTATUS retStatus() const { return __status; }

		KScopeRefByProcessByHandle() = default;
		KScopeRefByProcessByHandle(HANDLE h_process):KScopeRefByProcessByHandle() {
			__handle = h_process;
			__status = ObReferenceObjectByHandle(__handle, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode,
				&__process, 0);
		}
		void deref() {
			if (__process != nullptr) {
				ObDereferenceObject(__process);
			}
		}
	private:
		HANDLE __handle;
		void* __process;
		NTSTATUS __status;
	};

	class KScopeRefByThreadByHandle {
	public:
		void* get() const { return __thread; }
		NTSTATUS retStatus() const { return __status; }
		KScopeRefByThreadByHandle():__handle(0),__thread(0),__status(0){}

		KScopeRefByThreadByHandle(HANDLE h_process) :KScopeRefByThreadByHandle(){
		
			__handle = h_process;
			__status = ObReferenceObjectByHandle(__handle, PROCESS_ALL_ACCESS, *PsThreadType, KernelMode,
				&__thread, 0);
		}
		void deref() {
			if (__thread != nullptr) {
				ObDereferenceObject(__thread);
			}
		}
	private:
		HANDLE __handle;
		void* __thread;
		NTSTATUS __status;

	};
	class KScopeRefProcessByPid {
	public:
		KScopeRefProcessByPid(HANDLE pid):__pid(pid),__obj(nullptr){
			do {
				if (!NT_SUCCESS(__status = PsLookupProcessByProcessId(__pid,
					(PEPROCESS*)&__obj))) {
					break;

				}

			} while (false);
		
		}
		void* get()const  {
			return __obj;
		}
		void deref() {
			if(__obj)
				ObDereferenceObject(__obj);
		}
		NTSTATUS retStatus() const { return __status; }
	private:
		HANDLE __pid;
		void* __obj;
		NTSTATUS __status;
	};

	class KScopeRefThreadByTid {
	public:
		KScopeRefThreadByTid(HANDLE tid) :__tid(tid), __obj(nullptr) {
			do {
				if (!NT_SUCCESS(__status = PsLookupThreadByThreadId(__tid,
					(PETHREAD*)&__obj))) {
					break;

				}

			} while (false);

		}

		void* get()const {
			return __obj;
		}
		void deref() {
			if (__obj)
				ObDereferenceObject(__obj);
		}
		NTSTATUS retStatus() const { return __status; }
	private:
		HANDLE __tid;
		void* __obj;
		NTSTATUS __status;


	};

	class KScopeAttch {
	public:
		KScopeAttch(PEPROCESS process) :__process(process), __apc{},__need_def(0){
			//这种方式不需要obdef
			KeStackAttachProcess(__process, &__apc);
		}
		KScopeAttch(HANDLE pid) :__apc{}, __process{},__need_def(0) {
			__status = PsLookupProcessByProcessId(pid, &__process);
			if (NT_SUCCESS(__status)) {
				KeStackAttachProcess(__process, &__apc);
				//ObDereferenceObject(__process);
				__need_def = true;
			}
		}
		void* get() const { return __process; }
		NTSTATUS retStatus() const { return __status; }
		void deref() {
			if (__process && __need_def) {
				KeUnstackDetachProcess(&__apc);
				if(__need_def)
					ObDereferenceObject(__process);
			}
				

		}
	private:
		PEPROCESS __process;
		bool __need_def;
		KAPC_STATE __apc;
		NTSTATUS __status;
	};


	template<typename T>
	class KScopeRef {
	public:
		//必须让他发生隐式转换
		KScopeRef(const T& _ref) :__ref(_ref) {
			
		}
		~KScopeRef() {
			__ref.deref();
		}
		void* get() const { return __ref.get(); }
		NTSTATUS status() const { return __ref.status(); }
	private:
		T __ref;

	};

}