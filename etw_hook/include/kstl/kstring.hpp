#pragma once
#include <fltKernel.h>
#include <ntstrsafe.h>

/// <summary>
/// author :oxygen
/// </summary>
/// 
namespace kstd {


	template<typename T>
	class basic_string {
	public:
		union UNDEFINE_STRING
		{
			UNICODE_STRING us;
			ANSI_STRING as;
		};
		static const size_t npos = MAXULONG64;/*对比stl的npos*/
	public:
		basic_string() : __data(0), __size(0) {};
		basic_string(const T* str);
		basic_string(const basic_string& rhs);
		~basic_string();
	private:
		T* __data;
		size_t __size;/*以字节为单位*/
	public:
		//find函数
		size_t find(const T& c);
		size_t find(const basic_string& rhs);
		size_t find(const T* str);
		
		//rfind
		size_t rfind(const T& c);
		size_t rfind(const basic_string& rhs); //还未实现
		size_t rfind(const T* str);

		basic_string substr(size_t startPos, size_t endPos = npos/*如果这样,就一直到末尾*/);

		const T* c_str() const { return __data; }
		size_t size() const { return __size; }
		size_t length() const { return __size / sizeof(T) - 1; } //字符串长度 不包括\0
		T& operator[](int idx);
		basic_string& operator+=(const basic_string& rhs);
		basic_string& operator+=(const T* str);
		bool operator==(const basic_string& rhs) const;
		bool operator==(const T* str) const;

		basic_string& operator=(const basic_string& rhs);/*不考虑移动语义了*/

		basic_string& operator=(const T* str);
		UNDEFINE_STRING getXXString();/*特色功能*/
	private:
		T* __alloc(size_t bytes);
		void __free(T*);
	};

	
	template<typename T>
	inline basic_string<T>& kstd::basic_string<T>::operator=(const basic_string& rhs) {
		
		//清空原来的,防止内存泄露
		if (MmIsAddressValid(__data)) {
			__free(__data);
		}
		//不考虑移动语义
		__data = nullptr;
		__size = 0;

		auto p = __alloc(rhs.__size);
		if (!p) return *this;

		memset(p, 0, rhs.__size);
		memcpy(p, rhs.__data, rhs.__size);

		this->__size = rhs.__size;
		this->__data = p;

		return *this;
	}
	template<typename T>
	inline basic_string<T>& kstd::basic_string<T>::operator+=(const basic_string& rhs)
	{
	}


	template<typename T>
	inline basic_string<T>& kstd::basic_string<T>::operator+=(const T* str)
	{
		return operator+=(basic_string(str));
	}

	
	template<>
	inline basic_string<char>& kstd::basic_string<char>::operator+=(const basic_string& rhs) {
		auto newSize = __size + rhs.__size - sizeof(char);
		auto newPtr = __alloc(newSize);
		if (newPtr != nullptr) {
			memset(newPtr, 0, newSize);
			if(__size!=0)
				strcpy(newPtr, __data);
			if(rhs.__size!=0)
				strcat(newPtr, rhs.__data);
			__size = newSize;
			__free(__data);
			__data = newPtr;
		}

		return *this;

	}
	template<>
	inline basic_string<wchar_t>& kstd::basic_string<wchar_t>::operator+=(const basic_string& rhs) {
		auto newSize = __size + rhs.__size - sizeof(wchar_t);
		auto newPtr = __alloc(newSize);
		if (newPtr != nullptr) {
			memset(newPtr, 0, newSize);
			if (__size != 0)
				wcscpy(newPtr, __data);
			if (rhs.__size != 0)
				wcscat(newPtr, rhs.__data);
			__size = newSize;
			__free(__data);
			__data = newPtr;
		}

		return *this;
	}




	template<typename T>
	inline bool basic_string<T>::operator==(const basic_string& rhs) const
	{
		auto ret = false;
		do {

			if (&rhs == this) {
				ret = true;
				break;
			}
			if (rhs.size() != this->size()) {
				ret = false;
				break;
			}
			if (!MmIsAddressValid((PVOID)this->c_str()) || !MmIsAddressValid((PVOID)rhs.c_str())) {
				ret = false;
				break;
			}

			if (RtlCompareMemory(rhs.c_str(), this->c_str(), this->__size) == this->__size) {

				ret = true;
				break;
			}
			else {
				ret = false;
				break;
			}	

		} while (false);

		return ret;
		
	}

	template<typename T>
	inline bool basic_string<T>::operator==(const T* str) const
	{

		auto rhs = basic_string(str);
		return operator==(rhs);
	}

	template<typename T>
	inline T* basic_string<T>::__alloc(size_t bytes)
	{
		return reinterpret_cast<T*>(
			ExAllocatePoolWithTag(NonPagedPool, bytes, 'kstr')
			);
	}
	
	template<typename T>
	inline void basic_string<T>::__free(T* buf)
	{
		if(MmIsAddressValid(buf))
			ExFreePool(reinterpret_cast<void*>(buf));
	}


	template<typename T>
	inline T& kstd::basic_string<T>::operator[](int idx)
	{
		return __data[idx];
	}


	template<typename T>
	inline kstd::basic_string<T>::basic_string(const basic_string& rhs):__data(0), __size(0)
	{
		auto p=__alloc(rhs.__size);
		if (p == nullptr) {
			return;
		}
		memcpy(p, rhs.__data, rhs.__size);
		this->__size = rhs.__size;
		this->__data = p;
	}

	template<typename T>
	inline basic_string<T>::~basic_string()
	{
		if (MmIsAddressValid(__data)) __free(__data);
		__size = 0;
	}

	template<typename T>
	inline size_t basic_string<T>::find(const T& c)
	{
		
		auto ret = npos;
		for (auto i = 0ull; i < __size; i++) {
			if (__data[i] == c) {
				ret = i;
				break;
			}
		}
		return ret;
	}


	template<typename T>
	inline size_t basic_string<T>::find(const T* str)
	{
		return find(basic_string(str));
	}

	template<typename T>
	inline size_t basic_string<T>::rfind(const T& c)
	{
		auto ret = npos;
		for (auto i = __size-1; i >=0; i--) {
			if (__data[i] == c) {
				ret = i;
				break;
			}
		}
		return ret;
	}

	template<typename T>
	inline basic_string<T> basic_string<T>::substr(size_t startPos, size_t endPos)
	{
		do {
			auto idxMax = __size / sizeof(T) - 1/*这个idxMax是指向字符串的哪个\n字符*/;
			
			if (endPos == npos) {
				endPos = idxMax;
			}

			if (startPos > idxMax || endPos<startPos || endPos>idxMax) {
				break;
			}
		
			auto str = this->c_str();
			auto allocSize = (endPos - startPos + 1) * sizeof(T);
			auto p = __alloc(allocSize);
			if (p == nullptr) {
				break;
			}

			memset(p, 0, allocSize);
			memcpy(p, str + startPos, (endPos - startPos) * sizeof(T));
			auto ret = basic_string(p);
			__free(p);
			return ret;
		} while (false);

		//走到这就是失败
		return basic_string{};
	}




	template<>
	inline size_t basic_string<char>::find(const basic_string& rhs)
	{
		size_t ret = npos;
		do {
			if (rhs.__size == 0 || __size == 0) {
				break;
			}

			auto pos=strstr(this->__data, rhs.__data);
			if (pos == nullptr) {
				break;
			}

			auto interval = pos - this->__data;
			ret = interval;
		} while (false);
	
		return ret;
	}

	template<>
	inline size_t basic_string<wchar_t>::find(const basic_string& rhs)
	{
		size_t ret = npos;
		do {
			if (rhs.__size == 0 || __size == 0) {
				break;
			}

			auto pos = wcsstr(this->__data, rhs.__data);
			if (pos == nullptr) {
				break;
			}

			auto interval = pos - this->__data;
			ret = interval;
		} while (false);

		return ret;
	}

	/// <summary>
	/// 模板特化 
	/// </summary>
	/// <param name="str"></param>
	template<>
	inline basic_string<char>::basic_string(const char* str):__data(0),__size(0)
	{
		if (!MmIsAddressValid((PVOID)str)) return;

		auto len=strlen(str);
		auto p=__alloc(len*sizeof(char) + sizeof(char));
		if (p == nullptr) {
			//failed to alloc memory
			return;
		}
		__size = len * sizeof(char) + sizeof(char);
		memset(p, 0, __size);
		strcpy(p, str);
		__data = p;
	}

	/// <summary>
	/// 模板特化
	/// </summary>
	/// <param name="str"></param>
	template<>
	inline basic_string<wchar_t>::basic_string(const wchar_t* str) :__data(0), __size(0) {
		if (!MmIsAddressValid((PVOID)str)) return;

		auto len = wcslen(str);
		auto p = __alloc(len * sizeof(wchar_t) + sizeof(wchar_t));
		if (p == nullptr) {
			//failed to alloc memory
			return;
		}
		__size = len * sizeof(wchar_t) + sizeof(wchar_t);
		memset(p, 0, __size);
		wcscpy(p,str);
		__data = p;
	}






	template<typename T>
	inline basic_string<T>::basic_string(const T* str)
	{
	}



	template<>
	inline typename basic_string<char>::UNDEFINE_STRING basic_string<char>::getXXString()
	{
		UNDEFINE_STRING undefineS{};
		
		if (this->__data != nullptr) {
			RtlInitAnsiString(&undefineS.as, this->__data);
		}
		
		return undefineS;
	}
	
	template<>
	inline typename basic_string<wchar_t>::UNDEFINE_STRING basic_string<wchar_t>::getXXString()
	{
		UNDEFINE_STRING undefineS{};

		if (this->__data != nullptr) {
			RtlInitUnicodeString(&undefineS.us, this->__data);
		}

		return undefineS;
		
	}
	/// <summary>
	/// 模板偏特化
	/// </summary>
	/// <param name="str"></param>
	/// <returns></returns>
	template<>
	inline basic_string<wchar_t>& kstd::basic_string<wchar_t>::operator=(const wchar_t* str)
	{
		if (!MmIsAddressValid((PVOID)str)) return *this;

		__size = 0;
		if(MmIsAddressValid(__data))
			__free(__data);
		__data = 0;
		
		auto size = (wcslen(str) + 1) * sizeof(wchar_t);
		auto p = __alloc(size);
		if (p != nullptr) {
			memset(p, 0, size);
			wcscpy(p, str);
			__size = size;
			__data = p;
		}
		else {
			//failed to alloc memory
		}
		return *this;
	}

	template<>
	inline basic_string<char>& kstd::basic_string<char>::operator=(const char* str)
	{
		if (!MmIsAddressValid((PVOID)str)) return*this;

		__size = 0;
		if(MmIsAddressValid(__data))
			__free(__data);
		__data = 0;

		auto size = (strlen(str) + 1) * sizeof(char);
		auto p = __alloc(size);
		if (p != nullptr) {
			memset(p, 0, size);
			strcpy(p, str);
			__size = size;
			__data = p;
		}
		else {
			//failed to alloc memory
		}
		return *this;

	}



	using kstring = basic_string<char>;
	using kwstring = basic_string<wchar_t>;

}