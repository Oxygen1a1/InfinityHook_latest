#pragma once
#include <fltKernel.h>

/// <summary>
/// 实现类似stl的<memory> 多了个自己实现的kstd::move 用于移动语义!!
/// </summary>
namespace kstd {
#pragma warning(disable : 4996)
	static constexpr unsigned long km_pool_tag = 'Uptr';

	template<typename T>
	T&& move(T& v) {
		return static_cast<T&&>(v);
	}


	/*在这个里面自己实现new 和 delete 但是不是全局的 所以造成的缺点就是无法new 数组?*/
	namespace inner{
		template<typename T,typename... Args>
		T* __new(Args&&... args) {
			auto p = reinterpret_cast<T*>(ExAllocatePoolWithTag(NonPagedPool, sizeof(T), km_pool_tag));
			if (p != nullptr) {
				*p =T(args...);/*这个本身就是将亡值 因此自动触发移动语义?*/
			}
			return p;
		}

		template<typename T>
		void __delete(T* p)
		{
			if (p != nullptr) {
				ExFreePool(p);
			}
		}
	}

	template<typename T>
	struct DefaultDeleter {
		void operator() (T* p) {
			inner::__delete(p);
		}
	};

	template<class T, class Deleter = DefaultDeleter<T>>
	struct unique_ptr {


	public:
		unique_ptr() : __p(nullptr) {}

		unique_ptr(T* p) :__p(p) {}

		unique_ptr(const unique_ptr& rhs) = delete;/*普通的拷贝构造必须删除*/
		unique_ptr& operator= (const unique_ptr& rhs) = delete;

		//移动构造
		unique_ptr(unique_ptr&& rhs) {
			if (&rhs != this) {
				if (__p) {
					reset();/*先重置掉原先有的*/
				}
				this->__p = rhs.release();
			}
		}

		//移动复制
		unique_ptr& operator=  (unique_ptr&& rhs) {
			if (&rhs != this) {
				if (__p) {
					reset();/*先重置掉原先有的*/
				}
				this->__p = rhs.release();
			}

			return *this;
		}

		//DTOR
		~unique_ptr() {
			if (__p)
				Deleter{}(__p);
		}

		/*获取当前存储的资源*/
		T* get() const { return __p; }

		/*转移当前存储的资源*/
		T* release() {
			auto tmp = __p;
			__p = nullptr;
			return tmp;
		}

		/*释放当前存储的资源*/
		void reset(T* p = nullptr) {
			if (__p)
				Deleter{}(__p);
			__p = p;
		}

		//重载-> 和 * 描述符 这是每个智能智能必备的
		T& operator*() const {
			return *__p;
		}

		T* operator-> () const {
			return __p;
		}

	private:
		T* __p;
	};


	//make unique_ptr 也是必备的
	template<typename T, typename... Args>
	unique_ptr<T> make_unique(Args&&... args) {
		return unique_ptr<T>(inner::__new<T>(args...));
	}

#pragma warning(default : 4996)
}