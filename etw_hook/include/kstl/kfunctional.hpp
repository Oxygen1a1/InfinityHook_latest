#pragma once
//author :oxygen

namespace kstd {
#pragma warning(disable : 4996)
	static const long pool_tag = 'func';

	template<typename T>
	struct always_false {
	public:
		static constexpr bool value = false;
	};

	//上面的always_false就是为了让他返回失败 这个是默认的模板funtion类,默认一定是错误的，因为我们需要的是模板特化
	template<typename FuncSig>
	struct kfunction {

		static_assert(always_false<FuncSig>::value, "invalid function sig!");

	};

	//对于kfunction的特化
	template<typename Ret, typename... Args>
	struct kfunction<Ret(Args...)/*这个类型才不会触发静态断言*/> {

	private:
		/*提供接口,隐藏FuncType这个类型在上面的模板*/
		struct FuncBase {
			virtual Ret call(Args... args) = 0;
			virtual ~FuncBase() = default;
			void operator delete (void* p,size_t size) {
				//必须定义 因为FuncIpml会调用这个 内核没有全局delete!! 我们啥都不用干 因为这个类没有用重载new
				//但是必须得实现! 为什么呢? 因为我们保存的是这个玩意的指针,所以他会调用这个函数，但是这是个纯虚类,最终会
				//调用虚表到FuncImpl!
				__debugbreak();
				UNREFERENCED_PARAMETER(p);
				UNREFERENCED_PARAMETER(size);
			}
		};

		/*多态*/
		template<typename FuncType>
		struct FuncImpl : FuncBase {
		public:
			FuncImpl(FuncType func) : __func(func){}

			virtual Ret call(Args... args) override {
				
				return __func(args...);/*这里不考虑完美转发 内核没有std::forward*/
				
			}
			
			/*内部重载new*/
			void* operator new(size_t size) {
				return ExAllocatePoolWithTag(NonPagedPool, size, pool_tag);
			}
			
			void operator delete(void* p, size_t size) {
				
				if (p != nullptr && size != 0) {
					ExFreePool(p);
				}
			}

			FuncType __func;

		};

	public:

		kfunction():__fb(nullptr){}

		template<typename FuncType>
		kfunction(FuncType ft) : kfunction() {

			__fb = new FuncImpl<FuncType>(ft);
		}

		Ret operator()(Args&&... args) {
			if (__fb != nullptr)
				return __fb->call(args...);
			else return Ret();
		}

		~kfunction() {
			
			if (__fb) {
				delete __fb;
				__fb = nullptr;
			}
				
		}
	private:
		FuncBase* __fb;
	};

#pragma warning(default : 4996)
}