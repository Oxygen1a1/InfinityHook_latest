#pragma once
#include <fltKernel.h>


/// <summary>
/// author:oxygen
/// 一些自动的锁,基于RAII基质,把锁的指针(SpinLock Mutex EROUSE等等)填入进去,即可在一个作用域内进行自动枷锁解锁
/// </summary>
namespace kstd {

	//通过ERESOURCE进行同步
	class Resource {
	public:
		Resource(ERESOURCE* res) :__res(res) {}
		void acquire() {

			KeEnterCriticalRegion();
			ExAcquireResourceExclusiveLite(__res, TRUE);
		}

		void release() {

			ExReleaseResourceLite(__res);
			KeLeaveCriticalRegion();
		}
	private:
		ERESOURCE* __res;
	};

	class SpinLock {
	public:
		SpinLock(KSPIN_LOCK* lock):__spin_lock(lock),__irql(PASSIVE_LEVEL){}
		void acquire() {
			KeAcquireSpinLock(__spin_lock, &__irql);
		}
		void release() {
			KeReleaseSpinLock(__spin_lock, __irql);
		}
	private:
		KIRQL __irql;
		KSPIN_LOCK* __spin_lock;
	};
	//互斥体会让出时间片(调用KeWait)
	class Mutex {
	public:
		Mutex(KMUTEX* mutex):__mutex(mutex){}
		void acquire() {
			KeWaitForSingleObject(__mutex, Executive, KernelMode, false, NULL);

		}
		void release() {
			KeReleaseMutex(__mutex, false);
		}
	private:
		KMUTEX* __mutex;
	};
	//不能递归调用

	class FastMutex {
	public:
		FastMutex(FAST_MUTEX* f_mutex) :__fast_mutex(f_mutex){}
		void acquire() {
			ExAcquireFastMutex(__fast_mutex);

		}
		void release() {
			ExReleaseFastMutex(__fast_mutex);
		}
	private:
		FAST_MUTEX* __fast_mutex;
		//KIRQL __irql;
	};

	template<typename T>
	class AutoLock {
	public:
		AutoLock(const T& obj) : __obj(obj){
			__obj.acquire();
		}
		~AutoLock() {
			__obj.release();

		}
	private:
		T __obj;
	};
}