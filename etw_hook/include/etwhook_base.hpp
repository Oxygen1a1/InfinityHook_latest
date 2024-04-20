#pragma once
#ifndef _ETWHOOK_BASE_
#define _ETWHOOK_BASE_
#include <refs.hpp>

/*类基类*/
template <POOL_TYPE pool_type,ULONG pool_tag>
class _EtwBase {
public:
	void* operator new(size_t size);
	void  operator delete(void* p, size_t size);
};


template<POOL_TYPE pool_type, ULONG pool_tag>
inline void* _EtwBase<pool_type, pool_tag>::operator new(size_t size)
{
	return kalloc<char>(pool_type, size, pool_tag);
}

template<POOL_TYPE pool_type, ULONG pool_tag>
inline void _EtwBase<pool_type, pool_tag>::operator delete(void* p, size_t size) 
{
	UNREFERENCED_PARAMETER(size);
	return ExFreePool(p);
}

using EtwBase = _EtwBase<NonPagedPool, 'ewth'>;

#endif