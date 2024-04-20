#pragma once
#include <fltKernel.h>

/// <summary>
/// author :oxygen
/// 这个是线程安全的  必须先初始化
/// this is thread-safty list,but must init first
/// </summary>




namespace kstd {

	//有些东西必须自己实现,加个命名空间,不影响其他使用
	namespace list_inner {
		template<typename T, typename U>
		struct is_same {
			static constexpr bool value = false;
		};

		template<typename T>
		struct is_same<T, T> {
			static constexpr bool value = true;
		};

		template<typename T, typename U>
		constexpr bool is_same_v = is_same<T, U>::value;


	}

#define MUSTADDED 		void operator delete(void* p, size_t s) { \
	p,s; \
	KeBugCheckEx(1, 1, 1, 1, 1); \
	} \

#define POOL_TAG 'klst'
		enum class InsertType {
			head,
			tail
		};

		template<typename T>
		class Klist {
		private:
			class iterator {
			public:
				iterator(T* ptr,void* listHead) :__node(ptr), __listhead(listHead){}
				T& operator*() const { return *__node; }
				T* operator->() const { return __node; }
				iterator& operator++() {
					
					if (__node != nullptr) {

						auto tmp = __node->link.Flink;
						if (tmp == __listhead) {
							__node = nullptr;
						}
						else {
							__node = CONTAINING_RECORD(tmp, T, link);
						}
					}
			
					return *this;
				}
				bool operator==(const iterator& other)const { return other.__node == this->__node; }
				bool operator!=(const iterator& other)const { return other.__node != this->__node; }
			private:
				T* __node;
				void* __listhead;
			};
		public:
			void init();
			template<typename DestoryFunc>
			void destory(DestoryFunc func=nullptr);
			bool insert(const T& target,InsertType type);
			bool insert(T&& target, InsertType type);

			template<typename CompareFunc>
			T* find(const T& target,CompareFunc func);

			template<typename CompareFunc>
			void remove(const T& target, CompareFunc func);

			//从设计上 是不支持拷贝构造的 如果真的需要 以后再加 只不过以后需要大改
			Klist& operator=(const Klist& rhs)=delete;
			Klist(const Klist& rhs) = delete;

			//从设计上 是不支持移动语义的
			Klist& operator=(Klist&& rhs) = delete;
			Klist(Klist&& rhs) = delete;

			Klist() = default;
			ULONG size() const { return __size; }
			iterator begin();
			iterator end();
		private:
			LIST_ENTRY __listHead;
			KSPIN_LOCK __spinLock;
			ULONG __size;
			bool __inited;
		private:
			T&& move(T& v) const { return static_cast<T&&>(v); }
#pragma warning(disable : 4996)
			T* _alloc()const { 
				auto ret= (T*)ExAllocatePoolWithTag(NonPagedPool, sizeof(T), POOL_TAG);
				if (ret) memset(ret, 0, sizeof(T));
				return ret;
			};
#pragma warning(default : 4996)
			void _free(T* buf) const { ExFreePool(buf); };
		};


		template<typename T>
		inline void Klist<T>::init()
		{
			__inited = true;
			__size = 0;
			InitializeListHead(&__listHead);
			KeInitializeSpinLock(&__spinLock);
		}

		//移动语义支持
		template<typename T>
		inline bool Klist<T>::insert(T&& target, InsertType type) {
			
			auto ret = true;
			auto irql = KIRQL{};
			do {
				auto node = _alloc();
				if (node == nullptr) {
					ret = false;
					break;
				}

				*node = move(target);
				KeAcquireSpinLock(&__spinLock, &irql);
				switch (type)
				{
				case kstd::InsertType::head:
					InsertHeadList(&this->__listHead, &node->link);
					break;
				case kstd::InsertType::tail:
					InsertTailList(&this->__listHead, &node->link);
					break;
				default:
					ret = false;
					break;

				}
				KeReleaseSpinLock(&__spinLock, irql);
			} while (false);
			if (ret) __size++;

			return ret;
		}

		template<typename T>
		inline bool Klist<T>::insert(const T& target, InsertType type)
		{
			auto ret = true;
			auto irql = KIRQL{};
			do {
				auto node = _alloc();
				if (node == nullptr) {
					ret = false;
					break;
				}
				*node = target;
				KeAcquireSpinLock(&__spinLock,&irql);
				switch (type)
				{
				case kstd::InsertType::head:
					InsertHeadList(&this->__listHead, &node->link);
					break;
				case kstd::InsertType::tail:
					InsertTailList(&this->__listHead, &node->link);
					break;
				default:
					ret = false;
					break;

				}
				KeReleaseSpinLock(&__spinLock, irql);
			} while (false);
			if (ret) __size++;

			return ret;
		}


		template<typename T>
		inline typename Klist<T>::iterator Klist<T>::begin()
		{
			auto entry = CONTAINING_RECORD(&__listHead.Flink, T, link);

			return iterator(entry,(void*)&__listHead);
		}

		template<typename T>
		inline typename Klist<T>::iterator Klist<T>::end()
		{
			return iterator(nullptr,(void*)&__listHead);
		}



		template<typename T>
		template<typename DestoryFunc>
		inline void Klist<T>::destory(DestoryFunc func)
		{
			using namespace list_inner;

			auto irql = KIRQL{};
			KeAcquireSpinLock(&__spinLock, &irql);
			while (!IsListEmpty(&__listHead)) {

				auto head = RemoveHeadList(&__listHead);
				auto entry = CONTAINING_RECORD(head, T, link);
			
				if constexpr (list_inner::is_same_v<DestoryFunc, std::nullptr_t>) {
					//注意 msvc编译器如果显示调用析构函数，实际上是调用的
					entry->~T();
				}
				else {
					func(entry);
				}

				_free(entry);
			}
			KeReleaseSpinLock(&__spinLock, irql);
		}

		template<typename T>
		template<typename CompareFunc>
		inline T* Klist<T>::find(const T& compare, CompareFunc func)
		{
			T* ret=nullptr;
			auto irql = KIRQL{};

			KeAcquireSpinLock(&__spinLock, &irql);
			for (auto i=__listHead.Flink;i!=&__listHead;i=i->Flink) {
				auto entry = CONTAINING_RECORD(i, T, link/*必须具有这个字段 而且还得是LIST_ENTRY*/);
				if (func(compare,*entry)==true) {
					//find
					ret = entry;
					break;
				}

			}
			KeReleaseSpinLock(&__spinLock, irql);
			//not find
			return ret;
		}

		template<typename T>
		template<typename CompareFunc>
		inline void Klist<T>::remove(const T& target, CompareFunc func)
		{
			using namespace list_inner;

			auto f = find(target, func);
			if (f == nullptr) return;

			RemoveEntryList(&f->link);
			f->~T();/*调用析构函数*/
			_free(f);
			__size--;
			

			return;
		}

}
/// <summary>
/// author :oxygen
/// </summary>