#pragma once
#include <fltKernel.h>

/// <summary>
/// author:oxygen
/// 智能文件对象,类似C++提供的file对象 记得填写nt路径 而不是dos路径
/// </summary>
namespace kstd {

class Kfile
		{
		public:
			static const constexpr  int rdonly = 1;
			static const constexpr int wronly = 2;
			static const constexpr int rdwr = 4;
			static const constexpr int cretae = 8;/*不存在就创建*/
			static const constexpr int append = 0x10;/*追加*/
			static const constexpr int isdir = 0x100;/*是目录*/
			
		public:
			Kfile(const wchar_t* path, int open_mode,ULONG share_access=0);
			Kfile(const PUNICODE_STRING u_path, int open_mode, ULONG share_access=0);
			Kfile(const Kfile& rhs);/*拷贝构造 记得深拷贝*/
			Kfile& operator=(const Kfile& rhs);
			~Kfile();
			
		public:
			UNICODE_STRING getFileUPath()const { return __u_path; }
			wchar_t* getFilePath() const { return __p; }
			HANDLE getFileHandle() const { return __handle; }

			void seekg(const ULONG offset) { __offset = offset; }
			ULONG tellg() const { return __offset; }
			void close();
			bool read(void* buf, ULONG read_size);
			ULONG write(void* buf, ULONG buf_size);/*返回实际独到的*/
		private:
			bool open(ULONG share_acess = 0);
		private:
			static NTSTATUS createDirIter(const PUNICODE_STRING u_path);/*迭代地创建文件*/
			static NTSTATUS createDir(const PUNICODE_STRING u_path,HANDLE* h_file=nullptr);/*非迭代的创建*/
		private:
			HANDLE __handle;/*文件句柄*/
			wchar_t* __p;/*alloc申请 记得释放*/
			UNICODE_STRING __u_path;
			int __open_mode;
			ULONG __offset;
			ULONG __file_size;
			ULONG __share_access;
		};

		inline Kfile::Kfile(const wchar_t* path, const int open_mode,ULONG share_access):
		__handle(nullptr),__p(nullptr),__u_path({}), __open_mode(open_mode), __offset(0), __share_access(share_access)
		{
			const auto alloc_size = (wcslen(path) + 1) * sizeof(wchar_t);

			do
			{
				__p = reinterpret_cast<wchar_t*>(ExAllocatePoolWithTag(NonPagedPool, alloc_size, 'file'));
				if (__p == nullptr) break;

				memset(__p, 0, alloc_size);

				wcscpy(__p, path);
				RtlInitUnicodeString(&__u_path, __p);

				/*内部直接open 不放外部了*/
				open(__share_access);
			} while (false);
		}

		inline Kfile::Kfile(const PUNICODE_STRING u_path, int open_mode, ULONG share_access):
		__handle(nullptr), __p(nullptr), __u_path({}), __open_mode(open_mode), __offset(0),__share_access(share_access)
		{
			const auto alloc_size = (wcslen(u_path->Buffer) + 1) * sizeof(wchar_t);

			do
			{
				__p = reinterpret_cast<wchar_t*>(ExAllocatePoolWithTag(NonPagedPool, alloc_size, 'file'));
				if (__p == nullptr) break;

				memset(__p, 0, alloc_size);

				wcscpy(__p, u_path->Buffer);
				RtlInitUnicodeString(&__u_path, __p);

				/*内部直接open 不放外部了*/
				open(__share_access);
			} while (false);
		}

		inline Kfile::Kfile(const Kfile& rhs) :
			__handle(nullptr), __p(nullptr), __u_path({}), __open_mode(rhs.__open_mode),__offset(0),__share_access(rhs.__share_access)
		{
			if (rhs.__p == nullptr) return;

			const auto alloc_size = (wcslen(rhs.__p) + 1) * sizeof(wchar_t);

			do
			{
				
				__p = reinterpret_cast<wchar_t*>(ExAllocatePoolWithTag(NonPagedPool, alloc_size, 'file'));
				if (__p == nullptr) break;

				memset(__p, 0, alloc_size);

				wcscpy(__p, rhs.__p);
				RtlInitUnicodeString(&__u_path, __p);

				open(__share_access);
			} while (false);
		}


		inline Kfile& Kfile::operator=(const Kfile& rhs)
		{
			__handle = nullptr;
			__p = nullptr;
			__u_path = {};
			__open_mode = rhs.__open_mode;
			__offset = 0;
			__share_access = rhs.__share_access;

			if (rhs.__p == nullptr || &rhs==this/*self assign*/) return *this;

			const auto alloc_size = (wcslen(rhs.__p) + 1) * sizeof(wchar_t);

			do
			{

				__p = reinterpret_cast<wchar_t*>(ExAllocatePoolWithTag(NonPagedPool, alloc_size, 'file'));
				if (__p == nullptr) break;

				memset(__p, 0, alloc_size);

				wcscpy(__p, rhs.__p);
				RtlInitUnicodeString(&__u_path, __p);

				open(__share_access);
			} while (false);

			return *this;
		}

		inline Kfile::~Kfile()
		{
			if(__p!=nullptr)
			{
				ExFreePool(__p);
				__p = nullptr;

			}
			if(__handle!=nullptr)
			{
				ZwClose(__handle);
				__handle = nullptr;
			}
		}

		inline void Kfile::close()
		{
			if(__handle!=nullptr)
				ZwClose(__handle);
			__handle = nullptr;
		}

		inline bool Kfile::read(void* buf, ULONG read_size)
		{
			auto ret = false;
			if (read_size > __file_size - __offset || buf==nullptr) return false;

			IO_STATUS_BLOCK isb{};
			LARGE_INTEGER offset{ __offset };

			auto status = ZwReadFile(__handle, nullptr, nullptr, nullptr, &isb, buf, read_size, &offset, 0);
			if(NT_SUCCESS(status))
			{
				ret = true;
				__offset += read_size;
			}

			return ret;
		}

		inline ULONG Kfile::write(void* buf, ULONG buf_size)
		{
			auto ret = false;
			IO_STATUS_BLOCK isb{};
			LARGE_INTEGER offset{ __offset };
			auto status = ZwWriteFile(__handle, nullptr, nullptr,
				nullptr, &isb, buf, buf_size, &offset, 0);
			ZwFlushBuffersFile(__handle, &isb);
			
			if (NT_SUCCESS(status))
			{
				ret = true;
				__offset += buf_size;
			}

			return ret;
		}

		inline bool Kfile::open(ULONG share_access)
		{
			auto ret = false;
			auto access_flags = 0ul;
			auto create_disp_flags = 0ul;
			OBJECT_ATTRIBUTES oa{};
			IO_STATUS_BLOCK isb{};
			InitializeObjectAttributes(&oa, &this->__u_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);

			do
			{
				//先检查一下是否参数正确
				if (((__open_mode & Kfile::rdonly) && (__open_mode & Kfile::wronly)) ||
					((__open_mode & Kfile::rdonly) && (__open_mode & Kfile::append))
					) break;


				//处理目录
				if (__open_mode & Kfile::isdir)
				{
					if (__open_mode & Kfile::cretae)
					{
						//那么需要先创建一下
						Kfile::createDirIter(&this->__u_path);
					}
					//然后再打开这个目录
					if (NT_SUCCESS(Kfile::createDir(&this->__u_path, &__handle)))
					{
						ret = true;
						break;
					}
					else break;
				}

				//处理可读文件
				if (__open_mode & Kfile::rdonly)
				{
					access_flags |= GENERIC_READ;
				}
				if (__open_mode & Kfile::wronly)
				{
					access_flags |= GENERIC_WRITE;
				}
				if (__open_mode & Kfile::rdwr)
				{
					access_flags |= GENERIC_ALL;
				}
				if (__open_mode & Kfile::cretae)
				{
					if (__open_mode & Kfile::append) create_disp_flags |= FILE_OPEN_IF;
					else create_disp_flags |= FILE_OVERWRITE_IF;
				}
				else
				{
					create_disp_flags |= FILE_OPEN;
				}

				
				if (!NT_SUCCESS(ZwCreateFile(&this->__handle, access_flags, &oa, &isb,
					nullptr, FILE_ATTRIBUTE_NORMAL,
					share_access, create_disp_flags, 0, 0, 0))) break;

				FILE_STANDARD_INFORMATION file_info{};
				//开始询问文件大小
				if(!NT_SUCCESS(ZwQueryInformationFile(__handle, &isb, 
					&file_info, sizeof(file_info), FileStandardInformation)))
				{
					ZwClose(__handle);
					__handle=nullptr;
					ret=false;
					break;
				}

				//打开成功
				ret=true;
				__file_size=file_info.EndOfFile.LowPart;
				if (__open_mode & Kfile::append) __offset = __file_size;

			} while (false);

			return ret;
		}


		inline NTSTATUS Kfile::createDirIter(const PUNICODE_STRING u_path)
		{
			auto status = STATUS_UNSUCCESSFUL;

			if (u_path != nullptr)
			{

				for (auto i = 0ul; i < u_path->Length / sizeof(wchar_t); i++)
				{
					if (u_path->Buffer[i] == L'\\')
					{
						//find division
						//\\??\\C:\\lala\\haha
						auto tmp_path = reinterpret_cast<wchar_t*>(ExAllocatePoolWithTag(NonPagedPool,
							(i + 1) * sizeof(wchar_t), 'tmp'));
						auto u_tmp_path = UNICODE_STRING{};
						if (tmp_path != nullptr)
						{
							memset(tmp_path, 0, (i + 1) * sizeof(wchar_t));
							memcpy(tmp_path, u_path->Buffer, i * sizeof(wchar_t));
							RtlInitUnicodeString(&u_tmp_path, tmp_path);
							createDir(&u_tmp_path);
							ExFreePool(tmp_path);
						}
						else
						{

							break;
						}


					}


				}

				status = STATUS_SUCCESS;

			}

			return status;
		}

		inline NTSTATUS Kfile::createDir(const PUNICODE_STRING u_path, HANDLE* p_h_file)
		{
			
			auto status = STATUS_SUCCESS;
			auto h_file = HANDLE{};
			OBJECT_ATTRIBUTES oa{};
			IO_STATUS_BLOCK isb{};

			InitializeObjectAttributes(&oa, u_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);



			if (NT_SUCCESS(
				status = ZwCreateFile(&h_file, GENERIC_READ | GENERIC_WRITE, &oa, &isb, nullptr,
					FILE_ATTRIBUTE_DIRECTORY,
					FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
					FILE_OPEN_IF, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
					0, 0)
			)
				)
			{
				if (p_h_file != nullptr) *p_h_file = h_file;
				else status = ZwClose(h_file);

			}

			return status;
			
		}

}