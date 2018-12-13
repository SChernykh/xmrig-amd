/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018      Lee Clagett <https://github.com/vtnerd>
 * Copyright 2016-2018 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


#include <assert.h>
#include <sstream>


#include "common/cpu/Cpu.h"
#include "common/net/Job.h"
#include "Mem.h"
#include "crypto/CryptoNight.h"
#include "crypto/CryptoNight_test.h"
#include "crypto/CryptoNight_x86.h"
#include "net/JobResult.h"


alignas(16) cryptonight_ctx *CryptoNight::m_ctx = nullptr;
xmrig::Algo CryptoNight::m_algorithm = xmrig::CRYPTONIGHT;
xmrig::AlgoVerify CryptoNight::m_av  = xmrig::VERIFY_HW_AES;


bool CryptoNight::hash(const Job &job, JobResult &result, cryptonight_ctx *ctx)
{
    fn(job.algorithm().variant())(job.blob(), job.size(), result.result, &ctx, job.height());

    return *reinterpret_cast<uint64_t*>(result.result + 24) < job.target();
}


bool CryptoNight::init(xmrig::Algo algorithm)
{
    m_algorithm = algorithm;
    m_av        = xmrig::Cpu::info()->hasAES() ? xmrig::VERIFY_HW_AES : xmrig::VERIFY_SOFT_AES;

    return selfTest();
}


CryptoNight::cn_hash_fun CryptoNight::fn(xmrig::Algo algorithm, xmrig::AlgoVerify av, xmrig::Variant variant)
{
    using namespace xmrig;

    assert(variant >= VARIANT_0 && variant < VARIANT_MAX);

    static const cn_hash_fun func_table[VARIANT_MAX * 2 * 3] = {
        cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_0>,
        cryptonight_single_hash<CRYPTONIGHT, true,  VARIANT_0>,

        cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_1>,
        cryptonight_single_hash<CRYPTONIGHT, true,  VARIANT_1>,

        nullptr, nullptr, // VARIANT_TUBE

        cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_XTL>,
        cryptonight_single_hash<CRYPTONIGHT, true,  VARIANT_XTL>,

        cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_MSR>,
        cryptonight_single_hash<CRYPTONIGHT, true,  VARIANT_MSR>,

        nullptr, nullptr, // VARIANT_XHV

        cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_XAO>,
        cryptonight_single_hash<CRYPTONIGHT, true,  VARIANT_XAO>,

        cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_RTO>,
        cryptonight_single_hash<CRYPTONIGHT, true,  VARIANT_RTO>,

#       ifdef XMRIG_NO_ASM
        cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_2>,
#       else
        cryptonight_single_hash_asm<CRYPTONIGHT, VARIANT_2, ASM_AUTO>,
#       endif
        cryptonight_single_hash<CRYPTONIGHT, true, VARIANT_2>,

#       ifdef XMRIG_NO_ASM
        cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_4>,
#       else
        cryptonight_single_hash_asm<CRYPTONIGHT, VARIANT_4, ASM_AUTO>,
#       endif
        cryptonight_single_hash<CRYPTONIGHT, true, VARIANT_4>,

#       ifdef XMRIG_NO_ASM
        cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_4_64>,
#       else
        cryptonight_single_hash_asm<CRYPTONIGHT, VARIANT_4_64, ASM_AUTO>,
#       endif
        cryptonight_single_hash<CRYPTONIGHT, true, VARIANT_4_64>,

#       ifndef XMRIG_NO_AEON
        cryptonight_single_hash<CRYPTONIGHT_LITE, false, VARIANT_0>,
        cryptonight_single_hash<CRYPTONIGHT_LITE, true,  VARIANT_0>,

        cryptonight_single_hash<CRYPTONIGHT_LITE, false, VARIANT_1>,
        cryptonight_single_hash<CRYPTONIGHT_LITE, true,  VARIANT_1>,

        nullptr, nullptr, // VARIANT_TUBE
        nullptr, nullptr, // VARIANT_XTL
        nullptr, nullptr, // VARIANT_MSR
        nullptr, nullptr, // VARIANT_XHV
        nullptr, nullptr, // VARIANT_XAO
        nullptr, nullptr, // VARIANT_RTO
        nullptr, nullptr, // VARIANT_2
        nullptr, nullptr, // VARIANT_4
        nullptr, nullptr, // VARIANT_4_64
#       else
        nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr,
#       endif

#       ifndef XMRIG_NO_SUMO
        cryptonight_single_hash<CRYPTONIGHT_HEAVY, false, VARIANT_0>,
        cryptonight_single_hash<CRYPTONIGHT_HEAVY, true,  VARIANT_0>,

        nullptr, nullptr, // VARIANT_1

        cryptonight_single_hash<CRYPTONIGHT_HEAVY, false, VARIANT_TUBE>,
        cryptonight_single_hash<CRYPTONIGHT_HEAVY, true,  VARIANT_TUBE>,

        nullptr, nullptr, // VARIANT_XTL
        nullptr, nullptr, // VARIANT_MSR

        cryptonight_single_hash<CRYPTONIGHT_HEAVY, false, VARIANT_XHV>,
        cryptonight_single_hash<CRYPTONIGHT_HEAVY, true,  VARIANT_XHV>,

        nullptr, nullptr, // VARIANT_XAO
        nullptr, nullptr, // VARIANT_RTO
        nullptr, nullptr, // VARIANT_2
        nullptr, nullptr, // VARIANT_4
        nullptr, nullptr, // VARIANT_4_64
#       else
        nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr
#       endif
    };

    const size_t index = VARIANT_MAX * 2 * algorithm + 2 * variant + av - 1;

#   ifndef NDEBUG
    cn_hash_fun func = func_table[index];

    assert(index < sizeof(func_table) / sizeof(func_table[0]));
    assert(func != nullptr);

    return func;
#   else
    return func_table[index];
#   endif
}


bool CryptoNight::selfTest() {
    using namespace xmrig;

    MemInfo info = Mem::create(&m_ctx, m_algorithm, 1);

    if (m_algorithm == xmrig::CRYPTONIGHT) {
        return verify2(VARIANT_4, test_input_R) &&
               verify2(VARIANT_4_64, test_input_R_64) &&
               verify(VARIANT_0, test_output_v0) &&
               verify(VARIANT_1,   test_output_v1)  &&
               verify(VARIANT_2,   test_output_v2)  &&
               verify(VARIANT_XTL, test_output_xtl) &&
               verify(VARIANT_MSR, test_output_msr) &&
               verify(VARIANT_XAO, test_output_xao) &&
               verify(VARIANT_RTO, test_output_rto);
    }

#   ifndef XMRIG_NO_AEON
    if (m_algorithm == xmrig::CRYPTONIGHT_LITE) {
        return verify(VARIANT_0, test_output_v0_lite) &&
               verify(VARIANT_1, test_output_v1_lite);
    }
#   endif

#   ifndef XMRIG_NO_SUMO
    if (m_algorithm == xmrig::CRYPTONIGHT_HEAVY) {
        return verify(VARIANT_0,    test_output_v0_heavy)  &&
               verify(VARIANT_XHV,  test_output_xhv_heavy) &&
               verify(VARIANT_TUBE, test_output_tube_heavy);
    }
#   endif

    Mem::release(&m_ctx, 1, info);
    m_ctx = nullptr;

    return false;
}


bool CryptoNight::verify(xmrig::Variant variant, const uint8_t *referenceValue)
{
    if (!m_ctx) {
        return false;
    }

    uint8_t output[32];

    cn_hash_fun func = fn(variant);
    if (!func) {
        return false;
    }

    func(test_input, 76, output, &m_ctx, 0);

    return memcmp(output, referenceValue, 32) == 0;
}

bool CryptoNight::verify2(xmrig::Variant variant, const char *test_data)
{
    cn_hash_fun func = fn(variant);
    if (!func) {
        return false;
    }

    std::stringstream s(test_data);
    std::string expected_hex;
    std::string input_hex;
    uint64_t height;
    while (!s.eof())
    {
        uint8_t referenceValue[32];
        uint8_t input[256];

        s >> expected_hex;
        s >> input_hex;
        s >> height;

        if ((expected_hex.length() != 64) || (input_hex.length() > 512))
        {
            return false;
        }

        bool err = false;

        for (int i = 0; i < 32; ++i)
        {
            referenceValue[i] = (hf_hex2bin(expected_hex[i * 2], err) << 4) + hf_hex2bin(expected_hex[i * 2 + 1], err);
        }

        const size_t input_len = input_hex.length() / 2;
        for (size_t i = 0; i < input_len; ++i)
        {
            input[i] = (hf_hex2bin(input_hex[i * 2], err) << 4) + hf_hex2bin(input_hex[i * 2 + 1], err);
        }

        if (err)
        {
            return false;
        }

        uint8_t hash[32];
        func(input, input_len, hash, &m_ctx, height);
        if (memcmp(hash, referenceValue, sizeof(hash)) != 0)
        {
            return false;
        }
    }
    return true;
}
