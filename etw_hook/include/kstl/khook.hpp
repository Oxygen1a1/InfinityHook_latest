#pragma once
#include <fltKernel.h>
#include <intrin.h>
#include <ntimage.h>

//a simple kernel hook lib
//current contain driver object hook and kernel inline hook
namespace kstd {

	extern "C" {

		VOID KeGenericCallDpc(__in PKDEFERRED_ROUTINE Routine, __in_opt PVOID Context);

		VOID KeSignalCallDpcDone(__in PVOID SystemArgument1);

		LOGICAL KeSignalCallDpcSynchronize(__in PVOID SystemArgument2);

	}
	

#pragma warning(disable : 4996)
	// h disassambly engine
	namespace hde_inner {
		/* __cdecl */
		typedef INT8   int8_t;
		typedef INT16  int16_t;
		typedef INT32  int32_t;
		typedef INT64  int64_t;
		typedef UINT8  uint8_t;
		typedef UINT16 uint16_t;
		typedef UINT32 uint32_t;
		typedef UINT64 uint64_t;

#pragma pack(push,1)
		typedef struct {
			uint8_t len;
			uint8_t p_rep;
			uint8_t p_lock;
			uint8_t p_seg;
			uint8_t p_66;
			uint8_t p_67;
			uint8_t rex;
			uint8_t rex_w;
			uint8_t rex_r;
			uint8_t rex_x;
			uint8_t rex_b;
			uint8_t opcode;
			uint8_t opcode2;
			uint8_t modrm;
			uint8_t modrm_mod;
			uint8_t modrm_reg;
			uint8_t modrm_rm;
			uint8_t sib;
			uint8_t sib_scale;
			uint8_t sib_index;
			uint8_t sib_base;
			union {
				uint8_t imm8;
				uint16_t imm16;
				uint32_t imm32;
				uint64_t imm64;
			} imm;
			union {
				uint8_t disp8;
				uint16_t disp16;
				uint32_t disp32;
			} disp;
			uint32_t flags;
		} hde64s;
#pragma pack(pop)
		unsigned int hde64_disasm(const void* code, hde64s* hs);



	}



	class DrvObjHookManager {
	private:
		struct DrvObjInfo {

			void* base;
			void* entry_point;
			PDRIVER_OBJECT drv;
			void(*drvunload_callback)(PDRIVER_OBJECT, void* context);
			NTSTATUS(*drventry_callback)(PDRIVER_OBJECT, PUNICODE_STRING, void* context);
			LIST_ENTRY links;
			void* entry_context;
			void* unload_context;
			PDRIVER_UNLOAD org_unload;
			unsigned char org_bytes[14];
			bool is_exit;

		};

	public:

		static DrvObjHookManager* getInstance();

		//must called at img call back routine
		static NTSTATUS addDrvObjHook(void* img_base,
			NTSTATUS(*drventry_callback)(PDRIVER_OBJECT, PUNICODE_STRING, void* context),
			void(*drvunload_callback)(PDRIVER_OBJECT, void* context),
			void* entry_context=nullptr,void* unload_context=nullptr);

		//call this,it's will cancel drv unload hook
		static void removeDrvObjHook(void* img_base);

		//call this func will cancel all the drv unload hook and will clean up this instance
		static void destory();

	private:

		//helper function
		static void* getEntryPoint(void* img);
		static void* mapAddrByMdl(void* addr, size_t map_size, PMDL* mdl);
		static void unmapAddrByMdl(PMDL mdl);

		static DrvObjInfo* findDrvInfoByBase(void* entry_point);
		static NTSTATUS defaultDrvEntry(PDRIVER_OBJECT drv,PUNICODE_STRING u);
		static void defaultDrvUnload(PDRIVER_OBJECT drv);

	private:
		inline static bool __inited;
		inline static constexpr unsigned pool_tag = 'drvH';
		inline static LIST_ENTRY __head;
		inline static KSPIN_LOCK __lock;
		inline static DrvObjHookManager* __instance;
	};
	//driver object hook
	//can hook dispatch func,driver entry,driver unload, must init at 
	//you can exalloate memory and call init,can not call ctor or dtor!(it's only use at a ptr)
	
	//inline hook manager
	class InlineHookManager {
	public:
		// what callback sync memory
		enum class HookType {
			Dpc,
			Ipi,
		};
	private:
		typedef struct HookInfo {
			LIST_ENTRY links;
			void* hook_addr;
			void* trampline;
			unsigned char originalBytes[14];
			HookType type;
		}*pHookInfo;

		typedef struct IpiContext {
			unsigned char* modify_buf;
			unsigned char* modify_content;
			size_t modify_size;
			void* org_addr; /*hook addr org*/
			void** hk_addr;/*should modify this value in dpc or ipi callback*/
			void* tramp_line;
			volatile LONG done_cpu_count;
		}*pIpiContext;
		inline static constexpr int cover_size = 14/* inline hook cover 14 bytes*/;
	public:
		
		InlineHookManager() = delete;
		~InlineHookManager() = delete;
		static InlineHookManager* getInstance();
		static NTSTATUS init();
		static NTSTATUS inlinehook(void* target_addr, void** hk_addr,HookType hk_type=HookType::Dpc);
		static NTSTATUS destory();
		static NTSTATUS remove(void* target_addr);
		
	private:
		static NTSTATUS remove(pHookInfo hook_info);
		static void* mapAddrByMdl(void* addr, size_t map_size, PMDL* mdl);
		static void unmapAddrByMdl(PMDL mdl);
		static pHookInfo getHookInfoByAddr(void* target_addr);
		static ULONG_PTR ipiCallback(ULONG_PTR context);
		static void dpcCallback(_In_ struct _KDPC* Dpc,
			_In_opt_ PVOID DeferredContext,
			_In_opt_ PVOID SystemArgument1,
			_In_opt_ PVOID SystemArgument2);

	private:
		inline /*must define as inline*/ static InlineHookManager* __instance;
		inline static ULONG __cpu_count;
		inline static KSPIN_LOCK __spinlock;
		inline static LIST_ENTRY __head;
		inline static constexpr unsigned pool_tag = 0;
		inline static unsigned char __jmpcode[14] = { 0xff,0x25,0x00,0x00,0x00,0x00,0,0,0,0,0,0,0,0 };
		inline static bool __inited;
		inline static  void* __alloc_old;
		inline static void* __alloc_new;
	};

	namespace hde_inner {

		/*
 * Hacker Disassembler Engine 64 C
 * Copyright (c) 2008-2009, Vyacheslav Patkov.
 * All rights reserved.
 *
 */

#define C_NONE    0x00
#define C_MODRM   0x01
#define C_IMM8    0x02
#define C_IMM16   0x04
#define C_IMM_P66 0x10
#define C_REL8    0x20
#define C_REL32   0x40
#define C_GROUP   0x80
#define C_ERROR   0xff

#define PRE_ANY  0x00
#define PRE_NONE 0x01
#define PRE_F2   0x02
#define PRE_F3   0x04
#define PRE_66   0x08
#define PRE_67   0x10
#define PRE_LOCK 0x20
#define PRE_SEG  0x40
#define PRE_ALL  0xff

#define DELTA_OPCODES      0x4a
#define DELTA_FPU_REG      0xfd
#define DELTA_FPU_MODRM    0x104
#define DELTA_PREFIXES     0x13c
#define DELTA_OP_LOCK_OK   0x1ae
#define DELTA_OP2_LOCK_OK  0x1c6
#define DELTA_OP_ONLY_MEM  0x1d8
#define DELTA_OP2_ONLY_MEM 0x1e7

		static unsigned char hde64_table[] = {
		  0xa5,0xaa,0xa5,0xb8,0xa5,0xaa,0xa5,0xaa,0xa5,0xb8,0xa5,0xb8,0xa5,0xb8,0xa5,
		  0xb8,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xac,0xc0,0xcc,0xc0,0xa1,0xa1,
		  0xa1,0xa1,0xb1,0xa5,0xa5,0xa6,0xc0,0xc0,0xd7,0xda,0xe0,0xc0,0xe4,0xc0,0xea,
		  0xea,0xe0,0xe0,0x98,0xc8,0xee,0xf1,0xa5,0xd3,0xa5,0xa5,0xa1,0xea,0x9e,0xc0,
		  0xc0,0xc2,0xc0,0xe6,0x03,0x7f,0x11,0x7f,0x01,0x7f,0x01,0x3f,0x01,0x01,0xab,
		  0x8b,0x90,0x64,0x5b,0x5b,0x5b,0x5b,0x5b,0x92,0x5b,0x5b,0x76,0x90,0x92,0x92,
		  0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x6a,0x73,0x90,
		  0x5b,0x52,0x52,0x52,0x52,0x5b,0x5b,0x5b,0x5b,0x77,0x7c,0x77,0x85,0x5b,0x5b,
		  0x70,0x5b,0x7a,0xaf,0x76,0x76,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,
		  0x5b,0x5b,0x86,0x01,0x03,0x01,0x04,0x03,0xd5,0x03,0xd5,0x03,0xcc,0x01,0xbc,
		  0x03,0xf0,0x03,0x03,0x04,0x00,0x50,0x50,0x50,0x50,0xff,0x20,0x20,0x20,0x20,
		  0x01,0x01,0x01,0x01,0xc4,0x02,0x10,0xff,0xff,0xff,0x01,0x00,0x03,0x11,0xff,
		  0x03,0xc4,0xc6,0xc8,0x02,0x10,0x00,0xff,0xcc,0x01,0x01,0x01,0x00,0x00,0x00,
		  0x00,0x01,0x01,0x03,0x01,0xff,0xff,0xc0,0xc2,0x10,0x11,0x02,0x03,0x01,0x01,
		  0x01,0xff,0xff,0xff,0x00,0x00,0x00,0xff,0x00,0x00,0xff,0xff,0xff,0xff,0x10,
		  0x10,0x10,0x10,0x02,0x10,0x00,0x00,0xc6,0xc8,0x02,0x02,0x02,0x02,0x06,0x00,
		  0x04,0x00,0x02,0xff,0x00,0xc0,0xc2,0x01,0x01,0x03,0x03,0x03,0xca,0x40,0x00,
		  0x0a,0x00,0x04,0x00,0x00,0x00,0x00,0x7f,0x00,0x33,0x01,0x00,0x00,0x00,0x00,
		  0x00,0x00,0xff,0xbf,0xff,0xff,0x00,0x00,0x00,0x00,0x07,0x00,0x00,0xff,0x00,
		  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,
		  0x00,0x00,0x00,0xbf,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7f,0x00,0x00,
		  0xff,0x40,0x40,0x40,0x40,0x41,0x49,0x40,0x40,0x40,0x40,0x4c,0x42,0x40,0x40,
		  0x40,0x40,0x40,0x40,0x40,0x40,0x4f,0x44,0x53,0x40,0x40,0x40,0x44,0x57,0x43,
		  0x5c,0x40,0x60,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,
		  0x40,0x40,0x64,0x66,0x6e,0x6b,0x40,0x40,0x6a,0x46,0x40,0x40,0x44,0x46,0x40,
		  0x40,0x5b,0x44,0x40,0x40,0x00,0x00,0x00,0x00,0x06,0x06,0x06,0x06,0x01,0x06,
		  0x06,0x02,0x06,0x06,0x00,0x06,0x00,0x0a,0x0a,0x00,0x00,0x00,0x02,0x07,0x07,
		  0x06,0x02,0x0d,0x06,0x06,0x06,0x0e,0x05,0x05,0x02,0x02,0x00,0x00,0x04,0x04,
		  0x04,0x04,0x05,0x06,0x06,0x06,0x00,0x00,0x00,0x0e,0x00,0x00,0x08,0x00,0x10,
		  0x00,0x18,0x00,0x20,0x00,0x28,0x00,0x30,0x00,0x80,0x01,0x82,0x01,0x86,0x00,
		  0xf6,0xcf,0xfe,0x3f,0xab,0x00,0xb0,0x00,0xb1,0x00,0xb3,0x00,0xba,0xf8,0xbb,
		  0x00,0xc0,0x00,0xc1,0x00,0xc7,0xbf,0x62,0xff,0x00,0x8d,0xff,0x00,0xc4,0xff,
		  0x00,0xc5,0xff,0x00,0xff,0xff,0xeb,0x01,0xff,0x0e,0x12,0x08,0x00,0x13,0x09,
		  0x00,0x16,0x08,0x00,0x17,0x09,0x00,0x2b,0x09,0x00,0xae,0xff,0x07,0xb2,0xff,
		  0x00,0xb4,0xff,0x00,0xb5,0xff,0x00,0xc3,0x01,0x00,0xc7,0xff,0xbf,0xe7,0x08,
		  0x00,0xf0,0x02,0x00
		};


#define F_MODRM         0x00000001
#define F_SIB           0x00000002
#define F_IMM8          0x00000004
#define F_IMM16         0x00000008
#define F_IMM32         0x00000010
#define F_IMM64         0x00000020
#define F_DISP8         0x00000040
#define F_DISP16        0x00000080
#define F_DISP32        0x00000100
#define F_RELATIVE      0x00000200
#define F_ERROR         0x00001000
#define F_ERROR_OPCODE  0x00002000
#define F_ERROR_LENGTH  0x00004000
#define F_ERROR_LOCK    0x00008000
#define F_ERROR_OPERAND 0x00010000
#define F_PREFIX_REPNZ  0x01000000
#define F_PREFIX_REPX   0x02000000
#define F_PREFIX_REP    0x03000000
#define F_PREFIX_66     0x04000000
#define F_PREFIX_67     0x08000000
#define F_PREFIX_LOCK   0x10000000
#define F_PREFIX_SEG    0x20000000
#define F_PREFIX_REX    0x40000000
#define F_PREFIX_ANY    0x7f000000

#define PREFIX_SEGMENT_CS   0x2e
#define PREFIX_SEGMENT_SS   0x36
#define PREFIX_SEGMENT_DS   0x3e
#define PREFIX_SEGMENT_ES   0x26
#define PREFIX_SEGMENT_FS   0x64
#define PREFIX_SEGMENT_GS   0x65
#define PREFIX_LOCK         0xf0
#define PREFIX_REPNZ        0xf2
#define PREFIX_REPX         0xf3
#define PREFIX_OPERAND_SIZE 0x66
#define PREFIX_ADDRESS_SIZE 0x67



		/*
 * Hacker Disassembler Engine 64 C
 * Copyright (c) 2008-2009, Vyacheslav Patkov.
 * All rights reserved.
 *
 */
 // Integer types for HDE.
#if defined(_M_X64) || defined(__x86_64__)
#pragma warning(push, 0)
#pragma warning(disable: 4701 4706 26451)

		inline unsigned int hde64_disasm(const void* code, hde64s* hs)
		{
			uint8_t x, c, * p = (uint8_t*)code, cflags, opcode, pref = 0;
			uint8_t* ht = hde64_table, m_mod, m_reg, m_rm, disp_size = 0;
			uint8_t op64 = 0;

			// Avoid using memset to reduce the footprint.
			memset(hs, 0, sizeof(hde64s));

			for (x = 16; x; x--)
				switch (c = *p++) {
				case 0xf3:
					hs->p_rep = c;
					pref |= PRE_F3;
					break;
				case 0xf2:
					hs->p_rep = c;
					pref |= PRE_F2;
					break;
				case 0xf0:
					hs->p_lock = c;
					pref |= PRE_LOCK;
					break;
				case 0x26: case 0x2e: case 0x36:
				case 0x3e: case 0x64: case 0x65:
					hs->p_seg = c;
					pref |= PRE_SEG;
					break;
				case 0x66:
					hs->p_66 = c;
					pref |= PRE_66;
					break;
				case 0x67:
					hs->p_67 = c;
					pref |= PRE_67;
					break;
				default:
					goto pref_done;
				}
		pref_done:

			hs->flags = (uint32_t)pref << 23;

			if (!pref)
				pref |= PRE_NONE;

			if ((c & 0xf0) == 0x40) {
				hs->flags |= F_PREFIX_REX;
				if ((hs->rex_w = (c & 0xf) >> 3) && (*p & 0xf8) == 0xb8)
					op64++;
				hs->rex_r = (c & 7) >> 2;
				hs->rex_x = (c & 3) >> 1;
				hs->rex_b = c & 1;
				if (((c = *p++) & 0xf0) == 0x40) {
					opcode = c;
					goto error_opcode;
				}
			}

			if ((hs->opcode = c) == 0x0f) {
				hs->opcode2 = c = *p++;
				ht += DELTA_OPCODES;
			}
			else if (c >= 0xa0 && c <= 0xa3) {
				op64++;
				if (pref & PRE_67)
					pref |= PRE_66;
				else
					pref &= ~PRE_66;
			}

			opcode = c;
			cflags = ht[ht[opcode / 4] + (opcode % 4)];

			if (cflags == C_ERROR) {
			error_opcode:
				hs->flags |= F_ERROR | F_ERROR_OPCODE;
				cflags = 0;
				if ((opcode & -3) == 0x24)
					cflags++;
			}

			x = 0;
			if (cflags & C_GROUP) {
				uint16_t t;
				t = *(uint16_t*)(ht + (cflags & 0x7f));
				cflags = (uint8_t)t;
				x = (uint8_t)(t >> 8);
			}

			if (hs->opcode2) {
				ht = hde64_table + DELTA_PREFIXES;
				if (ht[ht[opcode / 4] + (opcode % 4)] & pref)
					hs->flags |= F_ERROR | F_ERROR_OPCODE;
			}

			if (cflags & C_MODRM) {
				hs->flags |= F_MODRM;
				hs->modrm = c = *p++;
				hs->modrm_mod = m_mod = c >> 6;
				hs->modrm_rm = m_rm = c & 7;
				hs->modrm_reg = m_reg = (c & 0x3f) >> 3;

				if (x && ((x << m_reg) & 0x80))
					hs->flags |= F_ERROR | F_ERROR_OPCODE;

				if (!hs->opcode2 && opcode >= 0xd9 && opcode <= 0xdf) {
					uint8_t t = opcode - 0xd9;
					if (m_mod == 3) {
						ht = hde64_table + DELTA_FPU_MODRM + t * 8;
						t = ht[m_reg] << m_rm;
					}
					else {
						ht = hde64_table + DELTA_FPU_REG;
						t = ht[t] << m_reg;
					}
					if (t & 0x80)
						hs->flags |= F_ERROR | F_ERROR_OPCODE;
				}

				if (pref & PRE_LOCK) {
					if (m_mod == 3) {
						hs->flags |= F_ERROR | F_ERROR_LOCK;
					}
					else {
						uint8_t* table_end, op = opcode;
						if (hs->opcode2) {
							ht = hde64_table + DELTA_OP2_LOCK_OK;
							table_end = ht + DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK;
						}
						else {
							ht = hde64_table + DELTA_OP_LOCK_OK;
							table_end = ht + DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK;
							op &= -2;
						}
						for (; ht != table_end; ht++)
							if (*ht++ == op) {
								if (!((*ht << m_reg) & 0x80))
									goto no_lock_error;
								else
									break;
							}
						hs->flags |= F_ERROR | F_ERROR_LOCK;
					no_lock_error:
						;
					}
				}

				if (hs->opcode2) {
					switch (opcode) {
					case 0x20: case 0x22:
						m_mod = 3;
						if (m_reg > 4 || m_reg == 1)
							goto error_operand;
						else
							goto no_error_operand;
					case 0x21: case 0x23:
						m_mod = 3;
						if (m_reg == 4 || m_reg == 5)
							goto error_operand;
						else
							goto no_error_operand;
					}
				}
				else {
					switch (opcode) {
					case 0x8c:
						if (m_reg > 5)
							goto error_operand;
						else
							goto no_error_operand;
					case 0x8e:
						if (m_reg == 1 || m_reg > 5)
							goto error_operand;
						else
							goto no_error_operand;
					}
				}

				if (m_mod == 3) {
					uint8_t* table_end;
					if (hs->opcode2) {
						ht = hde64_table + DELTA_OP2_ONLY_MEM;
						table_end = ht + sizeof(hde64_table) - DELTA_OP2_ONLY_MEM;
					}
					else {
						ht = hde64_table + DELTA_OP_ONLY_MEM;
						table_end = ht + DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM;
					}
					for (; ht != table_end; ht += 2)
						if (*ht++ == opcode) {
							if (*ht++ & pref && !((*ht << m_reg) & 0x80))
								goto error_operand;
							else
								break;
						}
					goto no_error_operand;
				}
				else if (hs->opcode2) {
					switch (opcode) {
					case 0x50: case 0xd7: case 0xf7:
						if (pref & (PRE_NONE | PRE_66))
							goto error_operand;
						break;
					case 0xd6:
						if (pref & (PRE_F2 | PRE_F3))
							goto error_operand;
						break;
					case 0xc5:
						goto error_operand;
					}
					goto no_error_operand;
				}
				else
					goto no_error_operand;

			error_operand:
				hs->flags |= F_ERROR | F_ERROR_OPERAND;
			no_error_operand:

				c = *p++;
				if (m_reg <= 1) {
					if (opcode == 0xf6)
						cflags |= C_IMM8;
					else if (opcode == 0xf7)
						cflags |= C_IMM_P66;
				}

				switch (m_mod) {
				case 0:
					if (pref & PRE_67) {
						if (m_rm == 6)
							disp_size = 2;
					}
					else
						if (m_rm == 5)
							disp_size = 4;
					break;
				case 1:
					disp_size = 1;
					break;
				case 2:
					disp_size = 2;
					if (!(pref & PRE_67))
						disp_size <<= 1;
				}

				if (m_mod != 3 && m_rm == 4) {
					hs->flags |= F_SIB;
					p++;
					hs->sib = c;
					hs->sib_scale = c >> 6;
					hs->sib_index = (c & 0x3f) >> 3;
					if ((hs->sib_base = c & 7) == 5 && !(m_mod & 1))
						disp_size = 4;
				}

				p--;
				switch (disp_size) {
				case 1:
					hs->flags |= F_DISP8;
					hs->disp.disp8 = *p;
					break;
				case 2:
					hs->flags |= F_DISP16;
					hs->disp.disp16 = *(uint16_t*)p;
					break;
				case 4:
					hs->flags |= F_DISP32;
					hs->disp.disp32 = *(uint32_t*)p;
				}
				p += disp_size;
			}
			else if (pref & PRE_LOCK)
				hs->flags |= F_ERROR | F_ERROR_LOCK;

			if (cflags & C_IMM_P66) {
				if (cflags & C_REL32) {
					if (pref & PRE_66) {
						hs->flags |= F_IMM16 | F_RELATIVE;
						hs->imm.imm16 = *(uint16_t*)p;
						p += 2;
						goto disasm_done;
					}
					goto rel32_ok;
				}
				if (op64) {
					hs->flags |= F_IMM64;
					hs->imm.imm64 = *(uint64_t*)p;
					p += 8;
				}
				else if (!(pref & PRE_66)) {
					hs->flags |= F_IMM32;
					hs->imm.imm32 = *(uint32_t*)p;
					p += 4;
				}
				else
					goto imm16_ok;
			}

			if (cflags & C_IMM16) {
			imm16_ok:
				hs->flags |= F_IMM16;
				hs->imm.imm16 = *(uint16_t*)p;
				p += 2;
			}
			if (cflags & C_IMM8) {
				hs->flags |= F_IMM8;
				hs->imm.imm8 = *p++;
			}

			if (cflags & C_REL32) {
			rel32_ok:
				hs->flags |= F_IMM32 | F_RELATIVE;
				hs->imm.imm32 = *(uint32_t*)p;
				p += 4;
			}
			else if (cflags & C_REL8) {
				hs->flags |= F_IMM8 | F_RELATIVE;
				hs->imm.imm8 = *p++;
			}

		disasm_done:

			if ((hs->len = (uint8_t)(p - (uint8_t*)code)) > 15) {
				hs->flags |= F_ERROR | F_ERROR_LENGTH;
				hs->len = 15;
			}

			return (unsigned int)hs->len;
		}
#pragma warning(pop)
#endif // defined(_M_X64) || defined(__x86_64__)

	}

	inline InlineHookManager* InlineHookManager::getInstance()
	{
		if (__instance == nullptr) {

			__instance = reinterpret_cast<InlineHookManager*>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof InlineHookManager, InlineHookManager::pool_tag));
		}
		
		return __instance;
	}

	inline NTSTATUS InlineHookManager::init()
	{
		auto status = STATUS_SUCCESS;

		if (__instance == nullptr) {
			status = STATUS_UNSUCCESSFUL;
			return status;
		}

		if (__inited == true) {
			status = STATUS_SUCCESS;
			return status;/*if has inited,return success directly*/
		}

		InitializeListHead(&__head);
		KeInitializeSpinLock(&__spinlock);

		__cpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);


		__inited = true;

		return status;
	}

	inline NTSTATUS InlineHookManager::inlinehook(void* target_addr, void** hk_addr /*this value should modify in ipi or dpc callback*/
	,HookType hk_type
	)
	{
		PMDL mdl = nullptr;
		auto status = STATUS_SUCCESS;
		pIpiContext ipi_context = nullptr;
		unsigned char* modify_content = nullptr;
		void* tramp_line = nullptr;
		ULONG copy_bytes_count = 0;
		hde_inner::hde64s hde{};
		unsigned char org_bytes[cover_size]{};
		KIRQL irql{};
		pHookInfo entry = nullptr;/* if failed  clean this */

		if (target_addr == nullptr || hk_addr == nullptr || *hk_addr == nullptr) {
			return STATUS_INVALID_PARAMETER;
		}
		
		if (__inited != true) {
			status = STATUS_ACPI_NOT_INITIALIZED;
			return status;
		}
		

		do {


			//map hook addr to write 
			auto modify_buf = mapAddrByMdl(target_addr, cover_size, &mdl);
			if (modify_buf == nullptr) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}



			//then exallcoatepool for trampline
			tramp_line = ExAllocatePoolWithTag(NonPagedPoolExecute, PAGE_SIZE, pool_tag);
			if (tramp_line == nullptr) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}


			//calcuate how many bytes copied to trampline and copy to the page
			while (copy_bytes_count < cover_size) {

				auto inst_len=hde_inner::hde64_disasm(reinterpret_cast<const void*>((UINT_PTR)target_addr + copy_bytes_count), &hde);
				if (inst_len == 0) break;
				copy_bytes_count += inst_len;
			}
			if (copy_bytes_count < cover_size) {
				status = STATUS_INSTRUCTION_MISALIGNMENT;
				break;
			}


			//set modify content(copy jmp code to this)
			modify_content = reinterpret_cast<unsigned char*>(ExAllocatePoolWithTag(NonPagedPoolNx, cover_size, pool_tag));
			if (modify_content == nullptr) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}


			::memcpy(modify_content, __jmpcode, sizeof __jmpcode);
			*((void**)(modify_content + 6)) = *hk_addr;


			//set trampline content
			::memcpy(tramp_line, target_addr, copy_bytes_count);
			::memcpy((unsigned char*)tramp_line + copy_bytes_count, __jmpcode, sizeof __jmpcode);
			RtlFillMemoryUlonglong((unsigned char*)tramp_line + copy_bytes_count + 6, 8, (UINT_PTR)target_addr + copy_bytes_count);

			//save org bytes
			::memcpy(org_bytes, target_addr, sizeof org_bytes);

			//alloate entry
			entry = reinterpret_cast<pHookInfo>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(HookInfo), pool_tag));
			if (entry == nullptr) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			
			//alloate modify_content buffer, and alloate ipi_context,then tragger ipi to sync the write
			ipi_context = reinterpret_cast<pIpiContext>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(IpiContext), pool_tag));
			if (!ipi_context) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			
			ipi_context->done_cpu_count = 0;
			ipi_context->modify_buf = (unsigned char*)modify_buf;
			ipi_context->modify_size = cover_size;
			ipi_context->modify_content = modify_content;
			ipi_context->org_addr = target_addr;/*this address we should __invlpg*/
			ipi_context->hk_addr = hk_addr;
			ipi_context->tramp_line = tramp_line;

			//generate ipi or dpc
			
			if (hk_type == HookType::Dpc) {
				KeGenericCallDpc(dpcCallback, ipi_context);
			}
			else {
				KeIpiGenericCall(ipiCallback, (ULONG_PTR)(ipi_context));
			}
			
			//finally insert the entry to the list tail,there is no possible be failed
			//*hk_addr = tramp_line; this will do in dpc or ipi callback

			entry->hook_addr = target_addr;
			entry->trampline = tramp_line;
			entry->type = hk_type;

			::memcpy(&entry->originalBytes, org_bytes, sizeof org_bytes);

			KeAcquireSpinLock(&__spinlock, &irql);
			InsertTailList(&__head,&entry->links);
			KeReleaseSpinLock(&__spinlock, irql);

		} while (false);

		//clean up;


		if (mdl != nullptr) {
			unmapAddrByMdl(mdl);
		}


		if (ipi_context != nullptr) {
			ExFreePool(ipi_context);
		}

		if (modify_content != nullptr) {
			ExFreePool(modify_content);
		}

		if (!NT_SUCCESS(status)) {
			if (entry != nullptr) {
				ExFreePool(entry);
			}
			if (tramp_line != nullptr) {
				ExFreePool(tramp_line);
			}
		}


		return status;
	}

	inline NTSTATUS InlineHookManager::destory()
	{
		auto status = STATUS_SUCCESS;
		auto irql = KIRQL{};

		if (__instance == nullptr || __inited == false) {
			status = STATUS_ACPI_NOT_INITIALIZED;
			return status;
		}

		KeAcquireSpinLock(&__spinlock, &irql);

		//traverse the list and remove it
		while (!IsListEmpty(&__head)) {
			auto link = RemoveHeadList(&__head);
			pHookInfo entry = CONTAINING_RECORD(link, HookInfo, links);

			InlineHookManager::remove(entry);
		}

		KeReleaseSpinLock(&__spinlock, irql);

		//clean instance
		if (__instance) {
			ExFreePool(__instance);
			__instance = nullptr;
		}

		__inited = false;
		return status;
	}

	//
	inline NTSTATUS InlineHookManager::remove(void* target_addr)
	{
		auto status = STATUS_ENTRYPOINT_NOT_FOUND;

		if (__inited == false) {
			status = STATUS_ACPI_NOT_INITIALIZED;
			return status;
		}

		auto irql = KIRQL{};
		
		auto hook_info = getHookInfoByAddr(target_addr);


		if (hook_info) {
			KeAcquireSpinLock(&__spinlock, &irql);

			RemoveEntryList(&hook_info->links);

			KeReleaseSpinLock(&__spinlock, irql);

			remove(hook_info);

			status = STATUS_SUCCESS;
		}

		return status;
	}

	//before call this func,makesure that you have unlinked the entry from the list;
	//this is a private func,user need to use remove(void*)
	inline NTSTATUS InlineHookManager::remove(pHookInfo hook_info)
	{
		auto status = STATUS_SUCCESS;
		IpiContext* ipi_context = nullptr;
		unsigned char* modify_content = nullptr;
		PMDL mdl = nullptr;
		if (__inited == false) {
			status = STATUS_ACPI_NOT_INITIALIZED;
			return status;
		}

		if (hook_info == nullptr) {
			status = STATUS_HASH_NOT_PRESENT;
			return status;
		}

		
		do {
			//alloc memory for ipi_context 
			ipi_context = reinterpret_cast<IpiContext*>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(IpiContext), pool_tag));

			if (ipi_context == nullptr) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}


			//alloc memory for moidfy_content
			modify_content = reinterpret_cast<unsigned char*>(ExAllocatePoolWithTag(NonPagedPoolNx, cover_size, pool_tag));
			if (modify_content == nullptr) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			//set modify content
			::memcpy(modify_content,hook_info->originalBytes ,cover_size);

			//map addr by mdl
			auto modify_buf = mapAddrByMdl(hook_info->hook_addr, cover_size, &mdl);
			if (modify_buf == nullptr) {
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			
			//fill ipi_context and generate an ipi
			ipi_context->done_cpu_count = 0;
			ipi_context->modify_content = modify_content;
			ipi_context->modify_size = cover_size;
			ipi_context->modify_buf = (unsigned char*)modify_buf;
			ipi_context->hk_addr = nullptr;
			ipi_context->tramp_line = nullptr;

			if (hook_info->type == HookType::Dpc) {

				KeGenericCallDpc(dpcCallback, ipi_context);

			}
			else {
				KeIpiGenericCall(ipiCallback, (ULONG_PTR)ipi_context);
			}

			//do not need to unlink the entry from the list
			//clean mem in innner
			if(hook_info->trampline!=nullptr)
				ExFreePool(hook_info->trampline);

			ExFreePool(hook_info);

		} while (false);

		//clean up
		if (ipi_context != nullptr) {
			ExFreePool(ipi_context);
		}
		if (modify_content != nullptr) {
			ExFreePool(modify_content);
		}
		if (mdl != nullptr) {
			unmapAddrByMdl(mdl);
		}

		return status;
	}



	inline void* InlineHookManager::mapAddrByMdl(void* addr, size_t map_size, PMDL* mdl)
	{
		void* map_buf = nullptr;
		PMDL _mdl = nullptr;

		if (addr == nullptr || map_size == 0 || mdl == nullptr || !MmIsAddressValid(addr)) {
			//DbgPrintEx(77, 0, "[+]check error addr -> %p\r\n", addr);
			return nullptr;
		}

		do {
			//DbgPrintEx(77, 0, "[+]addr ->%p\r\n",addr);

			_mdl = IoAllocateMdl(addr, (ULONG)map_size, 0, 0, nullptr);
			if (_mdl == nullptr) break;

			__try {

				MmProbeAndLockPages(_mdl, KernelMode, IoReadAccess);
				map_buf = MmGetSystemAddressForMdlSafe(_mdl, NormalPagePriority);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				map_buf = nullptr;
			}

			if (map_buf == nullptr) break;

			*mdl = _mdl;
			return map_buf;

		} while (false);
		
		//if can run here,failed

		if (map_buf != nullptr) {
			MmUnlockPages(_mdl);
		}
		if (_mdl) {
			IoFreeMdl(_mdl);
		}

		return nullptr;
	}

	inline void InlineHookManager::unmapAddrByMdl(PMDL mdl)
	{
		if (mdl != nullptr) {
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
		}
	}



	inline InlineHookManager::pHookInfo InlineHookManager::getHookInfoByAddr(void* target_addr)
	{
		pHookInfo ret = nullptr;
		KIRQL irql = {};
		//acuire the spin lock
		KeAcquireSpinLock(&__spinlock, &irql);
		//traverse all the entry from list and get hookinfo by addr

		for (auto link = __head.Flink; link != &__head; link = link->Flink) {

			auto entry = CONTAINING_RECORD(link, HookInfo, links);
			if (entry->hook_addr == target_addr) {
				ret = entry;
				break;
			}
		}

		//release the spin lock
		KeReleaseSpinLock(&__spinlock, irql);


		return ret;
	}


	// cpu idx==0的进行hook,一个cpu进来+1,hook的cpu hook完之后再+1 直到所有cpu+1,==cpu count之后,函数返回
	inline ULONG_PTR InlineHookManager::ipiCallback(ULONG_PTR context)
	{
		auto cur_cpu_idx = KeGetCurrentProcessorNumberEx(0);
		auto ipi_context = reinterpret_cast<pIpiContext>(context);
		auto done_cpu_value = 0;


		//single processor
		if (__cpu_count == 1) {

			::memcpy(ipi_context->modify_buf, ipi_context->modify_content, ipi_context->modify_size);
			if (MmIsAddressValid(ipi_context->hk_addr) || ipi_context->tramp_line != nullptr) {
				*ipi_context->hk_addr = ipi_context->tramp_line;
			}

			return 0;
		}

		if (cur_cpu_idx == 0) {
			//do hook
			//wait all the processor enter
			while (InterlockedCompareExchange(&ipi_context->done_cpu_count, __cpu_count - 1, __cpu_count - 1) != (LONG)__cpu_count - 1) {
				KeStallExecutionProcessor(25);
			}
			//all the processor enter ipi callback excpet current cpu,then modify mem
			::memcpy(ipi_context->modify_buf, ipi_context->modify_content, ipi_context->modify_size);


			if (MmIsAddressValid(ipi_context->hk_addr) || ipi_context->tramp_line != nullptr) {
				*ipi_context->hk_addr = ipi_context->tramp_line;
			}

			_InlineInterlockedAdd(&ipi_context->done_cpu_count, 1);
		}
		else {
			done_cpu_value = _InlineInterlockedAdd(&ipi_context->done_cpu_count, 1);


			//wait all the processor done
			while (InterlockedCompareExchange(&ipi_context->done_cpu_count, __cpu_count, __cpu_count) != (LONG)__cpu_count) {
				KeStallExecutionProcessor(25);
			}
		}

		//invaild tlb
		__invlpg(ipi_context->org_addr);
		return 0;
	}

	inline void InlineHookManager::dpcCallback(_In_ struct _KDPC* Dpc,
			_In_opt_ PVOID DeferredContext,
			_In_opt_ PVOID SystemArgument1,
			_In_opt_ PVOID SystemArgument2)
	{
		UNREFERENCED_PARAMETER(Dpc);

		auto cur_cpu_idx = KeGetCurrentProcessorNumberEx(0);
		auto ipi_context = reinterpret_cast<pIpiContext>(DeferredContext);
		auto done_cpu_value = 0;

		
		//single processor
		if (__cpu_count == 1) {

			::memcpy(ipi_context->modify_buf, ipi_context->modify_content, ipi_context->modify_size);
			if (MmIsAddressValid(ipi_context->hk_addr) || ipi_context->tramp_line!=nullptr) {
				*ipi_context->hk_addr = ipi_context->tramp_line;
			}

			return;
		}

		if (cur_cpu_idx == 0) {
			//do hook
			//wait all the processor enter
			while (InterlockedCompareExchange(&ipi_context->done_cpu_count, __cpu_count - 1, __cpu_count - 1) != (LONG)__cpu_count - 1) {
				KeStallExecutionProcessor(25);
			}
			//all the processor enter ipi callback excpet current cpu,then modify mem
			::memcpy(ipi_context->modify_buf, ipi_context->modify_content, ipi_context->modify_size);

			
			if (MmIsAddressValid(ipi_context->hk_addr) || ipi_context->tramp_line != nullptr) {
				*ipi_context->hk_addr = ipi_context->tramp_line;
			}

			_InlineInterlockedAdd(&ipi_context->done_cpu_count, 1);
		}
		else {
			done_cpu_value = _InlineInterlockedAdd(&ipi_context->done_cpu_count, 1);

			
			//wait all the processor done
			while (InterlockedCompareExchange(&ipi_context->done_cpu_count, __cpu_count, __cpu_count) != (LONG)__cpu_count) {
				KeStallExecutionProcessor(25);
			}
		}

		//invaild tlb
		__invlpg(ipi_context->org_addr);

		KeSignalCallDpcSynchronize(SystemArgument2);
		KeSignalCallDpcDone(SystemArgument1);

	}


	inline DrvObjHookManager* DrvObjHookManager::getInstance()
	{
		if (__instance == nullptr) {
			__instance = reinterpret_cast<DrvObjHookManager*>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof DrvObjHookManager, pool_tag));
			if (__instance) {

				KeInitializeSpinLock(&__lock);
				InitializeListHead(&__head);
				__inited = true;
			}
		}
		return __instance;
	}

	inline NTSTATUS DrvObjHookManager::addDrvObjHook(void* img_base, 
		NTSTATUS(*drventry_callback)(PDRIVER_OBJECT, PUNICODE_STRING, void* context), 
		void(*drvunload_callback)(PDRIVER_OBJECT, void* context), 
		void* entry_context,
		void* unload_context
	)
	{
		auto mdl = PMDL{};
		DrvObjInfo* entry = nullptr;
		auto status = STATUS_SUCCESS;
		auto irql = KIRQL{};

		if (img_base == nullptr || drventry_callback==nullptr || drvunload_callback==nullptr || __instance==nullptr) {
			status = STATUS_UNSUCCESSFUL;
			return status;
		}


		do {
			//alloate memory
			entry = reinterpret_cast<DrvObjInfo*>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof DrvObjInfo, pool_tag));
			if (!entry) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			memset(entry, 0, sizeof DrvObjInfo);

			unsigned char jmp_code[14] = { 0xff,0x25,0,0,0,0 };
			//hook driver entry and save org_bytes
			auto modify_buf = mapAddrByMdl(getEntryPoint(img_base), sizeof jmp_code, &mdl);
			if (!modify_buf) {
				status = STATUS_MAPPED_FILE_SIZE_ZERO;
				break;
			}

			memcpy(entry->org_bytes, getEntryPoint(img_base), sizeof entry->org_bytes);
			*reinterpret_cast<UINT64*>(jmp_code + 6) = (UINT64)defaultDrvEntry;
			memcpy(modify_buf, jmp_code, sizeof jmp_code);//hook

			//insert it to list
			entry->base = img_base;
			entry->drventry_callback = drventry_callback;
			entry->drvunload_callback = drvunload_callback;
			entry->unload_context = unload_context;
			entry->entry_context = entry_context;
			entry->entry_point = getEntryPoint(img_base);

			KeAcquireSpinLock(&__lock, &irql);

			InsertTailList(&__head, &entry->links);

			KeReleaseSpinLock(&__lock, irql);

		} while (0);

		//clean up
		if (mdl != nullptr) {
			unmapAddrByMdl(mdl);
		}

		if (!NT_SUCCESS(status)) {
			if(entry!=nullptr)
				ExFreePool(entry);
		}

		return status;
	}

	inline void DrvObjHookManager::removeDrvObjHook(void* img_base)
	{
		KIRQL irql = {};
		
		auto drvobj_info = findDrvInfoByBase(img_base);
		if (drvobj_info != nullptr) {
			KeAcquireSpinLock(&__lock, &irql);

			//must resume unload hook at driver does not unload
			if(!drvobj_info->is_exit)
				drvobj_info->drv->DriverUnload = drvobj_info->org_unload;
			 
			RemoveEntryList(&drvobj_info->links);

			KeReleaseSpinLock(&__lock, irql);

			ExFreePool(drvobj_info);
		}
	}


	inline void DrvObjHookManager::destory()
	{
		KIRQL irql = {};

		if (__instance && MmIsAddressValid(__instance)) {
			ExFreePool(__instance);
			
			KeAcquireSpinLock(&__lock, &irql);
			while (!IsListEmpty(&__head)) {

				auto link = RemoveEntryList(&__head);
				auto entry = CONTAINING_RECORD(link,DrvObjInfo, links);

				entry->drv->DriverUnload = entry->org_unload;
				ExFreePool(entry);
			}
			KeReleaseSpinLock(&__lock, irql);

			__inited = false;
			__instance = nullptr;
		}
	}

	inline void* DrvObjHookManager::getEntryPoint(void* img)
	{
		void* ret = nullptr;

		do {

			if (img == nullptr) break;

			auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(img);

			if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) break;

			auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>((UINT64)(img)+dos_header->e_lfanew);

			if (nt_headers->Signature != IMAGE_NT_SIGNATURE) break;

			ret = reinterpret_cast<void*>((UINT64)img + nt_headers->OptionalHeader.AddressOfEntryPoint);

		} while (0);

		return ret;
	}

	inline void* DrvObjHookManager::mapAddrByMdl(void* addr, size_t map_size, PMDL* mdl)
	{
		void* map_buf = nullptr;
		PMDL _mdl = nullptr;

		if (addr == nullptr || map_size == 0 || mdl == nullptr || !MmIsAddressValid(addr)) {
			return nullptr;
		}

		do {

			_mdl = IoAllocateMdl(addr, (ULONG)map_size, 0, 0, nullptr);
			if (_mdl == nullptr) break;

			__try {

				MmProbeAndLockPages(_mdl, KernelMode, IoReadAccess);
				map_buf = MmGetSystemAddressForMdlSafe(_mdl, NormalPagePriority);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				map_buf = nullptr;
			}

			if (map_buf == nullptr) break;

			*mdl = _mdl;
			return map_buf;

		} while (false);

		//if can run here,failed

		if (map_buf != nullptr) {
			MmUnlockPages(_mdl);
		}
		if (_mdl) {
			IoFreeMdl(_mdl);
		}

		return nullptr;
	}

	inline void DrvObjHookManager::unmapAddrByMdl(PMDL mdl)
	{
		if (mdl != nullptr) {
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
		}
	}

	inline DrvObjHookManager::DrvObjInfo* DrvObjHookManager::findDrvInfoByBase(void* img_base)
	{
		KIRQL irql = {  };
		DrvObjInfo* ret = nullptr;

		KeAcquireSpinLock(&__lock, &irql);
		
		for (auto link=__head.Flink;link!=&__head;link=link->Flink) {
			auto entry = CONTAINING_RECORD(link, DrvObjInfo, links);

			if (entry->base == img_base) {
				ret = entry;
				break;
			}
		}

		KeReleaseSpinLock(&__lock, irql);

		return ret;
	}

	inline NTSTATUS DrvObjHookManager::defaultDrvEntry(PDRIVER_OBJECT drv, PUNICODE_STRING u)
	{
		auto status = STATUS_SUCCESS;
		auto mdl = PMDL{};
		auto drvobj_info = findDrvInfoByBase(drv->DriverStart);

		if (drvobj_info == nullptr) {
			//fatal error
			return STATUS_UNSUCCESSFUL;
		}

		drvobj_info->drv = drv;

		do {

			//then resume hook bytes
			auto modify_buf = mapAddrByMdl(drvobj_info->entry_point, sizeof drvobj_info->org_bytes, &mdl);
			if (modify_buf == nullptr) {
				status = STATUS_MAPPED_FILE_SIZE_ZERO;
				break;
			}
			memcpy(modify_buf,drvobj_info->org_bytes ,sizeof drvobj_info->org_bytes);

			//call hook func
			status=drvobj_info->drventry_callback(drv, u, drvobj_info->entry_context);
			if (!NT_SUCCESS(status)) break;

			//call org func
			auto org_entry = reinterpret_cast<NTSTATUS(*)(PDRIVER_OBJECT, PUNICODE_STRING)>(drvobj_info->entry_point);
			status = org_entry(drv,u);
			if (!NT_SUCCESS(status)) {
				break;
			}


			//then hook driver unload and save org driver unload
			drvobj_info->org_unload = drv->DriverUnload;
			drv->DriverUnload = defaultDrvUnload;

		} while (0);


		//clean up
		if (mdl != nullptr) {
			unmapAddrByMdl(mdl);
		}

		//the driver will exit so clean entry from list
		if (!NT_SUCCESS(status)) {

			defaultDrvUnload(drv);

		}

		return status;
	}

	inline void DrvObjHookManager::defaultDrvUnload(PDRIVER_OBJECT drv)
	{
		auto drvobj_info = findDrvInfoByBase(drv->DriverStart);
		if (!drvobj_info) {
			//fatal error
			return;
		}

		//call hook driver unload
		drvobj_info->drvunload_callback(drv, drvobj_info->unload_context);

		drvobj_info->is_exit = true;

		auto org_unload = drvobj_info->org_unload;
		//clean this entry from list
		removeDrvObjHook(drvobj_info->base);

		//call org driver unload
		//if org_unload==nullptr maybe the driverentry return value is not success
		//so we should check the org_unload
		if(org_unload!=nullptr)
			org_unload(drv);
	}



#pragma warning(default : 4996)
}


