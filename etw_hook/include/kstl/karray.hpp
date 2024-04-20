#pragma once
#include <fltKernel.h>

/// <summary>
/// 自己实现类似std::array 
/// 不需要构造函数 里面的成员是唯一的
/// </summary>
namespace kstd {

	template<class _Tp,size_t _N>
	struct KArray {
		
		using iterator = _Tp*;
		using pointer = _Tp*;
		using const_iterator = _Tp const*;

	public:

		_Tp& operator[](size_t i) {
			return __element[i];
		}

		_Tp const& operator[](size_t i) const {
			return __element[i];
		}
		//STL内部都有 既有const版本的 也有非const版本的
		_Tp & at(size_t i) {
			return __element[i];
		}

		_Tp const & at(size_t i) const {
			return __element[i];
		}

		void fill(const _Tp& value) {
			for (size_t i = 0; i < _N; i++) {
				__element[i] = value;
			}
		}

		_Tp& front() {
			return __element[0];
		}

		_Tp const& front() const {
			return __element[0];
		}

		_Tp& back() {
			return __element[_N-1];
		}

		_Tp const& back()const  {
			return __element[_N-1];
		}

		constexpr size_t size()  const {
			return _N;
		}

		_Tp* data() const {
			return __element;
		}

		_Tp const * cdata() const {
			return __element;
		}

		_Tp*  begin() {
			return __element;
		}

		_Tp* end() {
			return __element + _N;
		}

	//必须要是public 因为可以直接{1,23,5}使用这种列表初始化 否则不行
		_Tp __element[_N];

	};

}