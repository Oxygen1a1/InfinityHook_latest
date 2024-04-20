#pragma once
#ifndef _KLOG_H_
#define  _KLOG_H_

//a very simple log lib
//author:oxygen

#include <fltKernel.h>
#include <ntstrsafe.h>
#pragma prefast(disable : 30030)
#pragma warning(disable: 4996)

namespace kstd {

	//只LOG到内核DebugPrint
#define LOG_DEBUG(format,...) \
	kstd::Logger::logPrint(kstd::Logger::LogLevel::Debug,__FUNCTION__,format,__VA_ARGS__)
#define LOG_INFO(format,...) \
	kstd::Logger::logPrint(kstd::Logger::LogLevel::Info,__FUNCTION__,format,__VA_ARGS__)
#define LOG_ERROR(format,...) \
	kstd::Logger::logPrint(kstd::Logger::LogLevel::Error,__FUNCTION__,format,__VA_ARGS__)

	//可以记录到文件
#define FLOG_INFO(format,...) \
	kstd::Logger::logPrint((kstd::Logger::LogLevel)(kstd::Logger::LogLevel::Info | kstd::Logger::LogLevel::ToFile),__FUNCTION__,format,__VA_ARGS__)
#define FLOG_DEBUG(format,...) \
	kstd::Logger::logPrint((kstd::Logger::LogLevel)(kstd::Logger::LogLevel::Debug | kstd::Logger::LogLevel::ToFile),__FUNCTION__,format,__VA_ARGS__)
#define FLOG_ERROR(format,...) \
	kstd::Logger::logPrint((kstd::Logger::LogLevel)(kstd::Logger::LogLevel::Error | kstd::Logger::LogLevel::ToFile),__FUNCTION__,format,__VA_ARGS__)
	
	//只记录到文件	
#define FLOG(format,...) \
	kstd::Logger::logPrint((kstd::Logger::LogLevel)(kstd::Logger::LogLevel::ToFile),__FUNCTION__,format,__VA_ARGS__)


	class Logger {
	public:
		enum LogLevel {
			Debug=1,
			Info=2,
			Error=4,
			ToFile=8,/*写到文件中*/
		};
	public:
		static void init(const char* info, const wchar_t* log_file_name);
		static void destory();
		static NTSTATUS logPrint(LogLevel log_level, const char* function_name,const char* format, ...);
		static void getCurSystemTime(char* buf, size_t size);
	private:
		inline static char __info[100];
		inline static HANDLE __hfile;
		inline static ULONG __offset;
	};

	inline void Logger::init(const char* info,const wchar_t* nt_log_file_path/*nt path,不要是dos path*/)
	{
		auto oa = OBJECT_ATTRIBUTES{};
		auto isb = IO_STATUS_BLOCK{};
		auto u_path = UNICODE_STRING{};

		RtlInitUnicodeString(&u_path, nt_log_file_path);
		InitializeObjectAttributes(&oa, &u_path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, 0);

		memcpy_s(__info, sizeof __info,info,strlen(info)+1);
		

		ZwCreateFile(&__hfile, GENERIC_WRITE, &oa, &isb, nullptr, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, 0, 0, 0);

	}

	inline void Logger::destory()
	{
		if (__hfile) {
			ZwClose(__hfile);
			__hfile = nullptr;
		}
	}

	NTSTATUS inline Logger::logPrint(LogLevel log_level, const char* function_name, const char* format, ...)
	{
		auto status = STATUS_SUCCESS;
		char log_message[412]{};
		char time[100]{};
		va_list args{};
		va_start(args, format);

		status = RtlStringCchVPrintfA(log_message, sizeof log_message, format, args);

		va_end(args);

		getCurSystemTime(time, sizeof time);

		char full_log_message[512] = {};
		RtlStringCchPrintfA(full_log_message, sizeof full_log_message, "%s\t[tid %d]\t[%s]\t", time, PsGetCurrentThreadId(), __info);

		if (NT_SUCCESS(status)) {
			if (log_level & LogLevel::Debug) {
				RtlStringCchCatA(full_log_message, sizeof full_log_message, "[debug]\tfunction name:\t");
				RtlStringCchCatA(full_log_message, sizeof full_log_message, function_name);
				RtlStringCchCatA(full_log_message, sizeof full_log_message, "\t");
			}
			else if (log_level & LogLevel::Error) {
				RtlStringCchCatA(full_log_message, sizeof full_log_message, "[error]\t");
			}
			else if (log_level & LogLevel::Info) {
				RtlStringCchCatA(full_log_message, sizeof full_log_message, "[Info]\t");
			}

			RtlStringCchCatA(full_log_message, sizeof full_log_message, log_message);

			if (log_level & LogLevel::ToFile && KeGetCurrentIrql()==PASSIVE_LEVEL) {
				IO_STATUS_BLOCK ioStatusBlock;
				LARGE_INTEGER offset;
				offset.QuadPart = __offset;

				ANSI_STRING logAnsiStr;
				RtlInitAnsiString(&logAnsiStr, full_log_message);

				UNICODE_STRING logUnicodeStr;
				RtlAnsiStringToUnicodeString(&logUnicodeStr, &logAnsiStr, TRUE);

				status = ZwWriteFile(__hfile, NULL, NULL, NULL, &ioStatusBlock, logUnicodeStr.Buffer, logUnicodeStr.Length, &offset, NULL);
				if (NT_SUCCESS(status)) {
					__offset += (ULONG)logUnicodeStr.Length;
				}

				RtlFreeUnicodeString(&logUnicodeStr);
			}

			DbgPrintEx(77, 0, full_log_message);
		}

		return status;
	}

	inline void Logger::getCurSystemTime(char* buf, size_t size)
	{
		LARGE_INTEGER sys_time{}, loacal_time{};
		TIME_FIELDS time_fields{};

		KeQuerySystemTime(&sys_time.QuadPart);
		ExSystemTimeToLocalTime(&sys_time, &loacal_time);
		RtlTimeToTimeFields(&loacal_time, &time_fields);
		sprintf_s(buf, size, "[%4d-%2d-%2d %2d:%2d:%2d.%3d]", time_fields.Year, time_fields.Month, time_fields.Day,
			time_fields.Hour, time_fields.Minute, time_fields.Second, time_fields.Milliseconds);

	}



}

#pragma warning(default : 4996)

#endif // !_KLOG_H_


