#pragma once
#define RTL_USE_AVL_TABLES 0
#include <fltKernel.h>

namespace kstd{

	//if you want to use this container,must add this MICRO in your class
#define MUSTADDED 		void operator delete(void* p, size_t s) { \
	p,s; \
	KeBugCheckEx(1, 1, 1, 1, 1); \
	} \


	template<typename T>
	class kavl {
	private:
		static const unsigned pool_tag = 'Kavl';
		static PVOID avlAlloc(RTL_AVL_TABLE* table, CLONG size);
		static VOID avlFree(RTL_AVL_TABLE* table, PVOID buf);
		static RTL_GENERIC_COMPARE_RESULTS avmCmpDefault(RTL_AVL_TABLE* table, PVOID first, PVOID second);
	private:
		T&& move(T& v) const { return static_cast<T&&>(v); }
	public:
		bool init(PRTL_AVL_COMPARE_ROUTINE cmp_func=kavl::avmCmpDefault);
		bool destory(void(*free_callback)(const T* item)=nullptr);

		bool insert(const T& item);
		bool insert(T&& item);

		T* find(const T& item);
		void remove(T* item);

		ULONG size();

		//只能通过下标遍历
		T& operator[](ULONG idx);

		//没有拷贝构造，移动语义 移动赋值 赋值 如果有需要 以后再加
		kavl() = default;
		~kavl() = default;
		kavl(const T& rhs) = delete;
		kavl(T&& rhs) = delete;
		kavl& operator=(const T& rhs) = delete;
		kavl& operator=(T&& rhs) = delete;
	private:
		PERESOURCE __lock;
		PRTL_AVL_TABLE __avl_table;
	};







	template<typename T>
	inline PVOID kavl<T>::avlAlloc(RTL_AVL_TABLE* table, CLONG size)
	{
		UNREFERENCED_PARAMETER(table);

		return ExAllocatePoolWithTag(NonPagedPool,size,pool_tag);
	}

	template<typename T>
	inline VOID kavl<T>::avlFree(RTL_AVL_TABLE* table, PVOID buf)
	{
		UNREFERENCED_PARAMETER(table);

		return ExFreePool(buf);
	}

	template<typename T>
	inline RTL_GENERIC_COMPARE_RESULTS kavl<T>::avmCmpDefault(RTL_AVL_TABLE* table, PVOID first, PVOID second)
	{
		UNREFERENCED_PARAMETER(table);

		if (*reinterpret_cast<T*>(first) == *reinterpret_cast<T*>(second)) return GenericEqual;
		else if (*reinterpret_cast<T*>(first) < *reinterpret_cast<T*>(second)) return GenericLessThan;
		else return GenericGreaterThan;
		
	}


	template<typename T>
	inline bool kavl<T>::init(PRTL_AVL_COMPARE_ROUTINE cmp_func)
	{
		
		__lock = reinterpret_cast<PERESOURCE>(ExAllocatePoolWithTag(NonPagedPool, sizeof ERESOURCE, pool_tag));
		if (!__lock) return false;
		__avl_table = reinterpret_cast<PRTL_AVL_TABLE>(ExAllocatePoolWithTag(NonPagedPool, sizeof RTL_AVL_TABLE, pool_tag));
		if (!__avl_table) {
			ExFreePool(__lock);
			return false;
		}

		RtlInitializeGenericTableAvl(__avl_table, cmp_func, avlAlloc, avlFree, nullptr);
		ExInitializeResourceLite(__lock);
		return true;
	}

	template<typename T>
	inline bool kavl<T>::destory(void(*free_callback)(const T* item))
	{
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(__lock, true);

		auto cnt = RtlNumberGenericTableElementsAvl(__avl_table);

		for (auto i = 0ul; i < cnt; i++) {
			auto node = RtlGetElementGenericTableAvl(__avl_table, 0);
			if (node) {
				if (free_callback != nullptr) {
					//use user manual free callback
					free_callback((const T*)node);
				}
				else {
					//directly call dtor
					reinterpret_cast<T*>(node)->~T();
				}

				RtlDeleteElementGenericTableAvl(__avl_table, node);
			}
			
		}
		ExReleaseResourceLite(__lock);
		KeLeaveCriticalRegion();

		ExDeleteResourceLite(__lock);
		if (this->__avl_table != nullptr) {
			ExFreePool(__avl_table);
			__avl_table = nullptr;
		}
		if (this->__lock != nullptr) {
			ExFreePool(__lock);
			__lock = nullptr;
		}

		return true;
	}

	template<typename T>
	inline bool kavl<T>::insert(const T& item)
	{
		bool suc = false;
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(__lock, true);

		auto ret = (T*)RtlInsertElementGenericTableAvl(__avl_table, (PVOID)&item, sizeof(T), nullptr);
		//这个函数是浅拷贝,一定要自己手动拷贝一下
		if (ret != nullptr) {
			memset(ret, 0, sizeof(T));
			*ret = item;
			suc = true;
		}

		ExReleaseResourceLite(__lock);
		KeLeaveCriticalRegion();
		return suc;
	}

	template<typename T>
	inline bool kavl<T>::insert(T&& item)
	{
		bool suc = false;
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(__lock, true);

		auto ret = (T*)RtlInsertElementGenericTableAvl(__avl_table, (PVOID)&item, sizeof(T), nullptr);
		//这个函数是浅拷贝,一定要自己手动拷贝一下
		if (ret != nullptr) {
			memset(ret, 0, sizeof(T));
			*ret = move(item);
			suc = true;
		}

		ExReleaseResourceLite(__lock);
		KeLeaveCriticalRegion();
		return suc;
	}


	template<typename T>
	inline T* kavl<T>::find(const T& item)
	{
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(__lock, true);
		
		auto f = reinterpret_cast<T*>(RtlLookupElementGenericTableAvl(__avl_table, (PVOID)&item));

		ExReleaseResourceLite(__lock);
		KeLeaveCriticalRegion();

		return f;
	}

	template<typename T>
	inline void kavl<T>::remove(T* item)
	{
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(__lock, true);

		if (MmIsAddressValid(item)) {
			//执行析构函数
			item->~T();
			RtlDeleteElementGenericTableAvl(__avl_table, item);
		}
			

		ExReleaseResourceLite(__lock);
		KeLeaveCriticalRegion();
	}


	template<typename T>
	inline ULONG kavl<T>::size()
	{
		return RtlNumberGenericTableElementsAvl(__avl_table);
	}

	template<typename T>
	inline T& kavl<T>::operator[](ULONG idx)
	{
		T* p = nullptr;
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(__lock, true);

		p = (T*)RtlGetElementGenericTableAvl(__avl_table, idx);

		ExReleaseResourceLite(__lock);
		KeLeaveCriticalRegion();

		if (MmIsAddressValid(p)) return *p;
		else {
			//Bug Check
			KeBugCheckEx(IRQL_NOT_GREATER_OR_EQUAL, 0x1111, 0x2222, 0x3333,0X1111);
		}
	}

}