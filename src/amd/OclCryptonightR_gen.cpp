#include <string>
#include <sstream>
#include <mutex>
#include "crypto/variant4_random_math.h"
#include "amd/OclCryptonightR_gen.h"
#include "amd/OclLib.h"
#include "amd/OclCache.h"

static std::string get_code(const V4_Instruction* code, int code_size)
{
    std::stringstream s;
	uint32_t prev_rot_src = (uint32_t)(-1);

	for (int i = 0; i < code_size; ++i)
    {
		const V4_Instruction inst = code[i];

		const uint32_t a = inst.dst_index;
		const uint32_t b = inst.src_index;

		switch (inst.opcode)
        {
		case MUL1:
		case MUL2:
		case MUL3:
			s << 'r' << a << "*=r" << b << ';';
			break;

		case ADD:
			{
				const int c = reinterpret_cast<const int8_t*>(code)[i + 1];
                s << 'r' << a << "+=r" << b << ((c < 0) ? '-' : '+');
				s << ((c < 0) ? -c : c) << ';';
			}
			break;

		case SUB:
            s << 'r' << a << "-=r" << b << ';';
			break;

		case ROR:
        case ROL:
            s << 'r' << a << "=rotate(r" << a << ((inst.opcode == ROR) ? ",ROT_BITS-r" : ",r") << b << ");";
			if (b != prev_rot_src)
            {
				prev_rot_src = b;
			}
			break;

		case XOR:
			s << 'r' << a << "^=r" << b << ';';
			break;
		}

		s << '\n';

        if (a == prev_rot_src)
        {
			prev_rot_src = (uint32_t)(-1);
		}
	}

    return s.str();
}

struct CacheEntry
{
    CacheEntry(xmrig::Variant variant, uint64_t height, std::string&& hash, cl_kernel kernel) :
        variant(variant),
        height(height),
        hash(std::move(hash)),
        kernel(kernel)
    {}

    xmrig::Variant variant;
    uint64_t height;
    std::string hash;
    cl_kernel kernel;
};

static std::mutex CryptonightR_cache_mutex;
static std::vector<CacheEntry> CryptonightR_cache;

#define KERNEL_NAME "cn1_cryptonight_r"

static void onBuildDone(cl_program program, void* data)
{
    CacheEntry* new_entry = reinterpret_cast<CacheEntry*>(data);

    cl_int ret;
    new_entry->kernel = OclLib::createKernel(program, KERNEL_NAME, &ret);
    if (ret != CL_SUCCESS)
    {
        return;
    }

    OclLib::releaseProgram(program);

    {
        std::lock_guard<std::mutex> g(CryptonightR_cache_mutex);

        // Check if the cache already has this kernel (some other thread might have added it first)
        for (const CacheEntry& entry : CryptonightR_cache)
        {
            if ((entry.variant == new_entry->variant) && (entry.height == new_entry->height) && (entry.hash == new_entry->hash))
            {
                OclLib::releaseKernel(new_entry->kernel);
                return;
            }
        }

        CryptonightR_cache.emplace_back(std::move(*new_entry));
    }

    delete new_entry;
}

cl_kernel CryptonightR_kernel(const GpuContext* ctx, xmrig::Variant variant, uint64_t height, bool precompile)
{
    if ((variant != xmrig::VARIANT_4) && (variant != xmrig::VARIANT_4_64))
    {
        return nullptr;
    }

    V4_Instruction code[256];
    const int code_size = v4_random_math_init(code, height);

    std::string source_code =
        #include "opencl/wolf-aes.cl"
        #include "opencl/cryptonight_r.cl"
    ;
    const char include_name[] = "XMRIG_INCLUDE_RANDOM_MATH";
    source_code.replace(source_code.find(include_name), sizeof(include_name) - 1, get_code(code, code_size));

    char options[512] = {};
    OclCache::get_options(xmrig::CRYPTONIGHT, ctx, options);

    if (variant == xmrig::VARIANT_4_64)
    {
        strcat(options, " -DRANDOM_MATH_64_BIT");
    }

    const char* s = source_code.c_str();
    std::string hash;
    OclCache::calc_hash(ctx->platformIdx, ctx->DeviceID, s, options, hash);

    {
        std::lock_guard<std::mutex> g(CryptonightR_cache_mutex);

        if (!precompile)
        {
            // Delete old cache entries
            for (size_t i = 0; i < CryptonightR_cache.size();)
            {
                const CacheEntry& entry = CryptonightR_cache[i];
                if ((entry.variant == variant) && (entry.height < height))
                {
                    OclLib::releaseKernel(entry.kernel);
                    CryptonightR_cache[i] = std::move(CryptonightR_cache.back());
                    CryptonightR_cache.pop_back();
                }
                else
                {
                    ++i;
                }
            }
        }

        // Check if cache has this kernel
        for (const CacheEntry& entry : CryptonightR_cache)
        {
            if ((entry.variant == variant) && (entry.height == height) && (entry.hash == hash))
            {
                return entry.kernel;
            }
        }
    }

    cl_int ret;
    cl_program program = OclLib::createProgramWithSource(ctx->opencl_ctx, 1, &s, nullptr, &ret);
    if (ret != CL_SUCCESS)
    {
        return nullptr;
    }

    if (precompile)
    {
        CacheEntry* entry = new CacheEntry(variant, height, std::move(hash), nullptr);
        OclLib::buildProgram(program, 1, &ctx->DeviceID, options, onBuildDone, entry);
        return nullptr;
    }

    if (OclLib::buildProgram(program, 1, &ctx->DeviceID, options) != CL_SUCCESS)
    {
        OclLib::releaseProgram(program);
        return nullptr;
    }

    if (OclCache::wait_build(program, ctx->DeviceID) != CL_SUCCESS)
    {
        OclLib::releaseProgram(program);
        return false;
    }

    cl_kernel kernel = OclLib::createKernel(program, KERNEL_NAME, &ret);
    OclLib::releaseProgram(program);

    if (ret != CL_SUCCESS)
    {
        return nullptr;
    }

    std::lock_guard<std::mutex> g(CryptonightR_cache_mutex);

    // Check if the cache already has this kernel (some other thread might have added it first)
    for (const CacheEntry& entry : CryptonightR_cache)
    {
        if ((entry.variant == variant) && (entry.height == height) && (entry.hash == hash))
        {
            OclLib::releaseKernel(kernel);
            return entry.kernel;
        }
    }

    CryptonightR_cache.emplace_back(variant, height, std::move(hash), kernel);

    return kernel;
}
