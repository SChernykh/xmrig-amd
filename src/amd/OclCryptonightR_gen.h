#ifndef __OCLCRYPTONIGHTR_GEN_H__
#define __OCLCRYPTONIGHTR_GEN_H__

#include "amd/GpuContext.h"

cl_kernel CryptonightR_kernel(const GpuContext* ctx, xmrig::Variant variant, uint64_t height, bool precompile = false);

#endif
