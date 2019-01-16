#include <cstring>
#include "crypto/variant4_random_math.h"

typedef void(*void_func)();

#include "crypto/asm/CryptonightR_template.h"
#include "crypto/asm/CryptonightR_64_template.h"
#include "Mem.h"

#ifndef XMRIG_ARM

static inline void add_code(uint8_t* &p, void (*p1)(), void (*p2)())
{
    const ptrdiff_t size = reinterpret_cast<const uint8_t*>(p2) - reinterpret_cast<const uint8_t*>(p1);
    if (size > 0) {
        memcpy(p, reinterpret_cast<void*>(p1), size);
        p += size;
    }
}

static inline void add_random_math(uint8_t* &p, const V4_Instruction* code, int code_size, const void_func* instructions, const void_func* instructions_mov, bool is_64_bit, xmrig::Assembly ASM)
{
    uint32_t prev_rot_src = (uint32_t)(-1);

    for (int i = 0;; ++i) {
        const V4_Instruction inst = code[i];
        if (inst.opcode == RET) {
            break;
        }

        V4_InstructionCompact op;
        op.opcode = (inst.opcode == MUL) ? inst.opcode : (inst.opcode + 2);
        op.dst_index = inst.dst_index;
        op.src_index = inst.src_index;

        const uint32_t a = inst.dst_index;
        const uint32_t b = inst.src_index;
        const uint8_t c = *reinterpret_cast<const uint8_t*>(&op);

        switch (inst.opcode) {
        case ROR:
        case ROL:
            if (b != prev_rot_src) {
                prev_rot_src = b;
                add_code(p, instructions_mov[c], instructions_mov[c + 1]);
            }
            break;
        }

        if (a == prev_rot_src) {
            prev_rot_src = (uint32_t)(-1);
        }

        void_func begin = instructions[c];

        if ((ASM = xmrig::ASM_BULLDOZER) && (inst.opcode == MUL) && !is_64_bit) {
            // AMD Bulldozer has latency 4 for 32-bit IMUL and 6 for 64-bit IMUL
            // Always use 32-bit IMUL for AMD Bulldozer in 32-bit mode - skip prefix 0x48 and change 0x49 to 0x41
            uint8_t* prefix = reinterpret_cast<uint8_t*>(begin);

            if (*prefix == 0x49) {
                *(p++) = 0x41;
            }

            begin = reinterpret_cast<void_func>(prefix + 1);
        }

        add_code(p, begin, instructions[c + 1]);

        if (inst.opcode == ADD) {
            *(uint32_t*)(p - sizeof(uint32_t) - (is_64_bit ? 3 : 0)) = inst.C;
        }
    }
}

void v4_compile_code(const V4_Instruction* code, int code_size, void* machine_code, xmrig::Assembly ASM)
{
    uint8_t* p0 = reinterpret_cast<uint8_t*>(machine_code);
    uint8_t* p = p0;

    add_code(p, CryptonightR_template_part1, CryptonightR_template_part2);
    add_random_math(p, code, code_size, instructions, instructions_mov, false, ASM);
    add_code(p, CryptonightR_template_part2, CryptonightR_template_part3);
    *(int*)(p - 4) = static_cast<int>((((const uint8_t*)CryptonightR_template_mainloop) - ((const uint8_t*)CryptonightR_template_part1)) - (p - p0));
    add_code(p, CryptonightR_template_part3, CryptonightR_template_end);

    Mem::flushInstructionCache(machine_code, p - p0);
}

void v4_64_compile_code(const V4_Instruction* code, int code_size, void* machine_code, xmrig::Assembly ASM)
{
    uint8_t* p0 = reinterpret_cast<uint8_t*>(machine_code);
    uint8_t* p = p0;

    add_code(p, CryptonightR_64_template_part1, CryptonightR_64_template_part2);
    add_random_math(p, code, code_size, instructions_64, instructions_64_mov, true, ASM);
    add_code(p, CryptonightR_64_template_part2, CryptonightR_64_template_part3);
    *(int*)(p - 4) = static_cast<int>((((const uint8_t*)CryptonightR_64_template_mainloop) - ((const uint8_t*)CryptonightR_64_template_part1)) - (p - p0));
    add_code(p, CryptonightR_64_template_part3, CryptonightR_64_template_end);

    Mem::flushInstructionCache(machine_code, p - p0);
}

void v4_compile_code_double(const V4_Instruction* code, int code_size, void* machine_code, xmrig::Assembly ASM)
{
    uint8_t* p0 = reinterpret_cast<uint8_t*>(machine_code);
    uint8_t* p = p0;

    add_code(p, CryptonightR_template_double_part1, CryptonightR_template_double_part2);
    add_random_math(p, code, code_size, instructions, instructions_mov, false, ASM);
    add_code(p, CryptonightR_template_double_part2, CryptonightR_template_double_part3);
    add_random_math(p, code, code_size, instructions, instructions_mov, false, ASM);
    add_code(p, CryptonightR_template_double_part3, CryptonightR_template_double_part4);
    *(int*)(p - 4) = static_cast<int>((((const uint8_t*)CryptonightR_template_double_mainloop) - ((const uint8_t*)CryptonightR_template_double_part1)) - (p - p0));
    add_code(p, CryptonightR_template_double_part4, CryptonightR_template_double_end);

    Mem::flushInstructionCache(machine_code, p - p0);
}

void v4_64_compile_code_double(const V4_Instruction* code, int code_size, void* machine_code, xmrig::Assembly ASM)
{
    uint8_t* p0 = reinterpret_cast<uint8_t*>(machine_code);
    uint8_t* p = p0;

    add_code(p, CryptonightR_64_template_double_part1, CryptonightR_64_template_double_part2);
    add_random_math(p, code, code_size, instructions_64, instructions_64_mov, true, ASM);
    add_code(p, CryptonightR_64_template_double_part2, CryptonightR_64_template_double_part3);
    add_random_math(p, code, code_size, instructions_64, instructions_64_mov, true, ASM);
    add_code(p, CryptonightR_64_template_double_part3, CryptonightR_64_template_double_part4);
    *(int*)(p - 4) = static_cast<int>((((const uint8_t*)CryptonightR_64_template_double_mainloop) - ((const uint8_t*)CryptonightR_64_template_double_part1)) - (p - p0));
    add_code(p, CryptonightR_64_template_double_part4, CryptonightR_64_template_double_end);

    Mem::flushInstructionCache(machine_code, p - p0);
}

#endif
