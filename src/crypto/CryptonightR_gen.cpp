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

static inline void add_random_math(uint8_t* &p, const V4_Instruction* code, int code_size, const void_func* instructions, const void_func* instructions_mov)
{
    uint32_t prev_rot_src = (uint32_t)(-1);
    const uint8_t* code1 = reinterpret_cast<const uint8_t*>(code);

    for (int i = 0; i < code_size; ++i) {
        const V4_Instruction inst = code[i];

        switch (inst.opcode) {
        case ROR:
        case ROL:
            if (inst.src_index != prev_rot_src) {
                prev_rot_src = inst.src_index;
                add_code(p, instructions_mov[code1[i]], instructions_mov[code1[i] + 1]);
            }
            break;
        }

        if (inst.dst_index == prev_rot_src) {
            prev_rot_src = (uint32_t)(-1);
        }

        add_code(p, instructions[code1[i]], instructions[code1[i] + 1]);

        if (inst.opcode == ADD) {
            *(p - 1) = code1[++i];
        }
    }
}

void v4_compile_code(const V4_Instruction* code, int code_size, void* machine_code)
{
    uint8_t* p0 = reinterpret_cast<uint8_t*>(machine_code);
    uint8_t* p = p0;

    add_code(p, CryptonightR_template_part1, CryptonightR_template_part2);
    add_random_math(p, code, code_size, instructions, instructions_mov);
    add_code(p, CryptonightR_template_part2, CryptonightR_template_part3);
    *(int*)(p - 4) = static_cast<int>((((const uint8_t*)CryptonightR_template_mainloop) - ((const uint8_t*)CryptonightR_template_part1)) - (p - p0));
    add_code(p, CryptonightR_template_part3, CryptonightR_template_end);

    Mem::FlushInstructionCache(machine_code, p - p0);
}

void v4_64_compile_code(const V4_Instruction* code, int code_size, void* machine_code)
{
    uint8_t* p0 = reinterpret_cast<uint8_t*>(machine_code);
    uint8_t* p = p0;

    add_code(p, CryptonightR_64_template_part1, CryptonightR_64_template_part2);
    add_random_math(p, code, code_size, instructions_64, instructions_64_mov);
    add_code(p, CryptonightR_64_template_part2, CryptonightR_64_template_part3);
    *(int*)(p - 4) = static_cast<int>((((const uint8_t*)CryptonightR_64_template_mainloop) - ((const uint8_t*)CryptonightR_64_template_part1)) - (p - p0));
    add_code(p, CryptonightR_64_template_part3, CryptonightR_64_template_end);

    Mem::FlushInstructionCache(machine_code, p - p0);
}

void v4_compile_code_double(const V4_Instruction* code, int code_size, void* machine_code)
{
    uint8_t* p0 = reinterpret_cast<uint8_t*>(machine_code);
    uint8_t* p = p0;

    add_code(p, CryptonightR_template_double_part1, CryptonightR_template_double_part2);
    add_random_math(p, code, code_size, instructions, instructions_mov);
    add_code(p, CryptonightR_template_double_part2, CryptonightR_template_double_part3);
    add_random_math(p, code, code_size, instructions, instructions_mov);
    add_code(p, CryptonightR_template_double_part3, CryptonightR_template_double_part4);
    *(int*)(p - 4) = static_cast<int>((((const uint8_t*)CryptonightR_template_double_mainloop) - ((const uint8_t*)CryptonightR_template_double_part1)) - (p - p0));
    add_code(p, CryptonightR_template_double_part4, CryptonightR_template_double_end);

    Mem::FlushInstructionCache(machine_code, p - p0);
}

void v4_64_compile_code_double(const V4_Instruction* code, int code_size, void* machine_code)
{
    uint8_t* p0 = reinterpret_cast<uint8_t*>(machine_code);
    uint8_t* p = p0;

    add_code(p, CryptonightR_64_template_double_part1, CryptonightR_64_template_double_part2);
    add_random_math(p, code, code_size, instructions_64, instructions_64_mov);
    add_code(p, CryptonightR_64_template_double_part2, CryptonightR_64_template_double_part3);
    add_random_math(p, code, code_size, instructions_64, instructions_64_mov);
    add_code(p, CryptonightR_64_template_double_part3, CryptonightR_64_template_double_part4);
    *(int*)(p - 4) = static_cast<int>((((const uint8_t*)CryptonightR_64_template_double_mainloop) - ((const uint8_t*)CryptonightR_64_template_double_part1)) - (p - p0));
    add_code(p, CryptonightR_64_template_double_part4, CryptonightR_64_template_double_end);

    Mem::FlushInstructionCache(machine_code, p - p0);
}

#endif
