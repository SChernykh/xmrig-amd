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

#ifndef __CRYPTONIGHT_TEST_H__
#define __CRYPTONIGHT_TEST_H__


const static uint8_t test_input[380] = {
    0x03, 0x05, 0xA0, 0xDB, 0xD6, 0xBF, 0x05, 0xCF, 0x16, 0xE5, 0x03, 0xF3, 0xA6, 0x6F, 0x78, 0x00,
    0x7C, 0xBF, 0x34, 0x14, 0x43, 0x32, 0xEC, 0xBF, 0xC2, 0x2E, 0xD9, 0x5C, 0x87, 0x00, 0x38, 0x3B,
    0x30, 0x9A, 0xCE, 0x19, 0x23, 0xA0, 0x96, 0x4B, 0x00, 0x00, 0x00, 0x08, 0xBA, 0x93, 0x9A, 0x62,
    0x72, 0x4C, 0x0D, 0x75, 0x81, 0xFC, 0xE5, 0x76, 0x1E, 0x9D, 0x8A, 0x0E, 0x6A, 0x1C, 0x3F, 0x92,
    0x4F, 0xDD, 0x84, 0x93, 0xD1, 0x11, 0x56, 0x49, 0xC0, 0x5E, 0xB6, 0x01,
    0x01, 0x00, 0xFB, 0x8E, 0x8A, 0xC8, 0x05, 0x89, 0x93, 0x23, 0x37, 0x1B, 0xB7, 0x90, 0xDB, 0x19,
    0x21, 0x8A, 0xFD, 0x8D, 0xB8, 0xE3, 0x75, 0x5D, 0x8B, 0x90, 0xF3, 0x9B, 0x3D, 0x55, 0x06, 0xA9,
    0xAB, 0xCE, 0x4F, 0xA9, 0x12, 0x24, 0x45, 0x00, 0x00, 0x00, 0x00, 0xEE, 0x81, 0x46, 0xD4, 0x9F,
    0xA9, 0x3E, 0xE7, 0x24, 0xDE, 0xB5, 0x7D, 0x12, 0xCB, 0xC6, 0xC6, 0xF3, 0xB9, 0x24, 0xD9, 0x46,
    0x12, 0x7C, 0x7A, 0x97, 0x41, 0x8F, 0x93, 0x48, 0x82, 0x8F, 0x0F, 0x02,
    0x07, 0x07, 0xB4, 0x87, 0xD0, 0xD6, 0x05, 0x26, 0xE0, 0xC6, 0xDD, 0x9B, 0xC7, 0x18, 0xC3, 0xCF,
    0x52, 0x04, 0xBD, 0x4F, 0x9B, 0x27, 0xF6, 0x73, 0xB9, 0x3F, 0xEF, 0x7B, 0xB2, 0xF7, 0x2B, 0xBB,
    0x3F, 0x3E, 0x9C, 0x3E, 0x9D, 0x33, 0x1E, 0xDE, 0xAD, 0xBE, 0xEF, 0x4E, 0x00, 0x91, 0x81, 0x29,
    0x74, 0xB2, 0x70, 0xE7, 0x6D, 0xD2, 0x2A, 0x5F, 0x52, 0x04, 0x93, 0xE6, 0x18, 0x89, 0x40, 0xD8,
    0xC6, 0xE3, 0x90, 0x6E, 0xAA, 0x6A, 0xB7, 0xE2, 0x08, 0x7E, 0x78, 0x0E,
    0x01, 0x00, 0xEE, 0xB2, 0xD1, 0xD6, 0x05, 0xFF, 0x27, 0x7F, 0x26, 0xDB, 0xAA, 0xB2, 0xC9, 0x26,
    0x30, 0xC6, 0xCF, 0x11, 0x64, 0xEA, 0x6C, 0x8A, 0xE0, 0x98, 0x01, 0xF8, 0x75, 0x4B, 0x49, 0xAF,
    0x79, 0x70, 0xAE, 0xEE, 0xA7, 0x62, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x47, 0x8C, 0x63, 0xE7, 0xD8,
    0x40, 0x02, 0x3C, 0xDA, 0xEA, 0x92, 0x52, 0x53, 0xAC, 0xFD, 0xC7, 0x8A, 0x4C, 0x31, 0xB2, 0xF2,
    0xEC, 0x72, 0x7B, 0xFF, 0xCE, 0xC0, 0xE7, 0x12, 0xD4, 0xE9, 0x2A, 0x01,
    0x07, 0x07, 0xA9, 0xB7, 0xD1, 0xD6, 0x05, 0x3F, 0x0D, 0x5E, 0xFD, 0xC7, 0x03, 0xFC, 0xFC, 0xD2,
    0xCE, 0xBC, 0x44, 0xD8, 0xAB, 0x44, 0xA6, 0xA0, 0x3A, 0xE4, 0x4D, 0x8F, 0x15, 0xAF, 0x62, 0x17,
    0xD1, 0xE0, 0x92, 0x85, 0xE4, 0x73, 0xF9, 0x00, 0x00, 0x00, 0xA0, 0xFC, 0x09, 0xDE, 0xAB, 0xF5,
    0x8B, 0x6F, 0x1D, 0xCA, 0xA8, 0xBA, 0xAC, 0x74, 0xDD, 0x74, 0x19, 0xD5, 0xD6, 0x10, 0xEC, 0x38,
    0xCF, 0x50, 0x29, 0x6A, 0x07, 0x0B, 0x93, 0x8F, 0x8F, 0xA8, 0x10, 0x04
};

const static char* test_input_R = R"===(
da8b319c5305ee30c4427f6d92fc022eadf64d6ddc190a98f76f340e36501947 5468697320697320612074657374205468697320697320612074657374205468697320697320612074657374 1806260
5651baabf26ce6a54e1fd151b6569cba720c353f9fc58af365aaebc55269afe0 4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e67 1806261
2962bf37adbfea15929b937a208e13975b3cfaa4d45b6c0c9e3cb83382587bf6 656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f7265 1806262
31be4ac4701e3f2687d13623b77842b1f3a7f63ffa8eff1f8779b051fcff4aa7 657420646f6c6f7265206d61676e6120616c697175612e20557420656e696d206164206d696e696d2076656e69616d2c 1806263
842dd9bc384f46700ff5b451b8fd6d123c24b9bd559813e65b40cbc5b6fd4e24 71756973206e6f737472756420657865726369746174696f6e20756c6c616d636f206c61626f726973206e697369 1806264
470684872a046ac5934f8fa6d14ce16b6dab3068cf5f7c1db4c878deac3319e0 757420616c697175697020657820656120636f6d6d6f646f20636f6e7365717561742e20447569732061757465 1806265
b3e98b59ed7e114356ab1b437b607bc2420cb650d6993d75b5027cfb341d7e65 697275726520646f6c6f7220696e20726570726568656e646572697420696e20766f6c7570746174652076656c6974 1806266
492cd553721b23337b30ef163336dc4411f6331d929be113a465dbabbe3794a6 657373652063696c6c756d20646f6c6f726520657520667567696174206e756c6c612070617269617475722e 1806267
9e5406153d8419dbecf083a460e161ad88c3d51bc6dd28df7303ef1b81cf76c9 4578636570746575722073696e74206f6363616563617420637570696461746174206e6f6e2070726f6964656e742c 1806268
f28575078964f99e4f8177373faf6a0b62d056e161289df048c83a4dd017b9fd 73756e7420696e2063756c706120717569206f666669636961206465736572756e74206d6f6c6c697420616e696d20696420657374206c61626f72756d2e 1806269
)===";

const static char* test_input_R_64 = R"===(
26ad83a9a50037d7ad70d2a54962cc30c45060a05ff52cced758178dc2f77f99 5468697320697320612074657374205468697320697320612074657374205468697320697320612074657374 1806260
3bbcc383b287171a4cca7c09cb17988fd857263c71f401b1e4b9bf2acd0f297d 4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e67 1806261
fdb2d6b3966d925e3b845833efbc45cc518626ab1f645f3743fbcca962c6191c 656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f7265 1806262
3600ed4ea5ee3c3eacef76ed86c2d5938f28aeb7f5cedf7e9e55b066f827f1b2 657420646f6c6f7265206d61676e6120616c697175612e20557420656e696d206164206d696e696d2076656e69616d2c 1806263
b1ba5591a8e4ba382bfd82f31ec704cb44c0e6c4f57915d9cc7ef5886fdd280c 71756973206e6f737472756420657865726369746174696f6e20756c6c616d636f206c61626f726973206e697369 1806264
7962f55351e3390d09bbf107bbe256abf55343ee54042efdfad76129cd55936d 757420616c697175697020657820656120636f6d6d6f646f20636f6e7365717561742e20447569732061757465 1806265
f77e77f4ce11eeea052a44847998441a7a2d576fab7187b99e85f885f0cf7cde 697275726520646f6c6f7220696e20726570726568656e646572697420696e20766f6c7570746174652076656c6974 1806266
1268fab6ec94a7022eb235cac2a7e4a6edf3ed972902036ff89e3158dc5b6770 657373652063696c6c756d20646f6c6f726520657520667567696174206e756c6c612070617269617475722e 1806267
da91553d01df07a7be7493868ac6e5cea7a8bdaffa4928f49757b2bcdd084fcc 4578636570746575722073696e74206f6363616563617420637570696461746174206e6f6e2070726f6964656e742c 1806268
d3da10d5697286cd9b701bcc8c575e194332b6d1680ff064a6c901d2eeefcd81 73756e7420696e2063756c706120717569206f666669636961206465736572756e74206d6f6c6c697420616e696d20696420657374206c61626f72756d2e 1806269
)===";


const static uint8_t test_output_v0[160] = {
    0x1A, 0x3F, 0xFB, 0xEE, 0x90, 0x9B, 0x42, 0x0D, 0x91, 0xF7, 0xBE, 0x6E, 0x5F, 0xB5, 0x6D, 0xB7,
    0x1B, 0x31, 0x10, 0xD8, 0x86, 0x01, 0x1E, 0x87, 0x7E, 0xE5, 0x78, 0x6A, 0xFD, 0x08, 0x01, 0x00,
    0x1B, 0x60, 0x6A, 0x3F, 0x4A, 0x07, 0xD6, 0x48, 0x9A, 0x1B, 0xCD, 0x07, 0x69, 0x7B, 0xD1, 0x66,
    0x96, 0xB6, 0x1C, 0x8A, 0xE9, 0x82, 0xF6, 0x1A, 0x90, 0x16, 0x0F, 0x4E, 0x52, 0x82, 0x8A, 0x7F,
    0xA1, 0xB4, 0xFA, 0xE3, 0xE5, 0x76, 0xCE, 0xCF, 0xB7, 0x9C, 0xAF, 0x3E, 0x29, 0x92, 0xE4, 0xE0,
    0x31, 0x24, 0x05, 0x48, 0xBF, 0x8D, 0x5F, 0x7B, 0x11, 0x03, 0x60, 0xAA, 0xD7, 0x50, 0x3F, 0x0C,
    0x2D, 0x30, 0xF3, 0x87, 0x4F, 0x86, 0xA1, 0x4A, 0xB5, 0xA2, 0x1A, 0x08, 0xD0, 0x44, 0x2C, 0x9D,
    0x16, 0xE9, 0x28, 0x49, 0xA1, 0xFF, 0x85, 0x6F, 0x12, 0xBB, 0x7D, 0xAB, 0x11, 0x1C, 0xE7, 0xF7,
    0x2D, 0x9D, 0x19, 0xE4, 0xD2, 0x26, 0x44, 0x1E, 0xCD, 0x22, 0x08, 0x24, 0xA8, 0x97, 0x46, 0x62,
    0x04, 0x84, 0x90, 0x4A, 0xEE, 0x99, 0x14, 0xED, 0xB8, 0xC6, 0x0D, 0x37, 0xA1, 0x66, 0x17, 0xB0
};


// Cryptonight variant 1 (Monero v7)
const static uint8_t test_output_v1[160] = {
    0xF2, 0x2D, 0x3D, 0x62, 0x03, 0xD2, 0xA0, 0x8B, 0x41, 0xD9, 0x02, 0x72, 0x78, 0xD8, 0xBC, 0xC9,
    0x83, 0xAC, 0xAD, 0xA9, 0xB6, 0x8E, 0x52, 0xE3, 0xC6, 0x89, 0x69, 0x2A, 0x50, 0xE9, 0x21, 0xD9,
    0xC9, 0xFA, 0xE8, 0x42, 0x5D, 0x86, 0x88, 0xDC, 0x23, 0x6B, 0xCD, 0xBC, 0x42, 0xFD, 0xB4, 0x2D,
    0x37, 0x6C, 0x6E, 0xC1, 0x90, 0x50, 0x1A, 0xA8, 0x4B, 0x04, 0xA4, 0xB4, 0xCF, 0x1E, 0xE1, 0x22,   
    0xE7, 0x8C, 0x5A, 0x6E, 0x38, 0x30, 0x68, 0x4A, 0x73, 0xFC, 0x1B, 0xC6, 0x6D, 0xFC, 0x8D, 0x98,
    0xB4, 0xC2, 0x23, 0x39, 0xAD, 0xE0, 0x9D, 0xF6, 0x6D, 0x8C, 0x6A, 0xAA, 0xF9, 0xB2, 0xE3, 0x4C,
    0xB6, 0x90, 0x6C, 0xE6, 0x15, 0x5E, 0x46, 0x07, 0x9C, 0xB2, 0x6B, 0xAC, 0x3B, 0xAC, 0x1A, 0xDE,
    0x92, 0x2C, 0xD6, 0x0C, 0x46, 0x9D, 0x9B, 0xC2, 0x84, 0x52, 0x65, 0xF6, 0xBD, 0xFA, 0x0D, 0x74,
    0x00, 0x66, 0x10, 0x07, 0xF1, 0x19, 0x06, 0x3A, 0x6C, 0xFF, 0xEE, 0xB2, 0x40, 0xE5, 0x88, 0x2B,
    0x6C, 0xAB, 0x6B, 0x1D, 0x88, 0xB8, 0x44, 0x25, 0xF4, 0xEA, 0xB7, 0xEC, 0xBA, 0x12, 0x8A, 0x24
};


// Cryptonight variant 2 (Monero v8)
const static uint8_t test_output_v2[160] = {
    0x97, 0x37, 0x82, 0x82, 0xCF, 0x10, 0xE7, 0xAD, 0x03, 0x3F, 0x7B, 0x80, 0x74, 0xC4, 0x0E, 0x14,
    0xD0, 0x6E, 0x7F, 0x60, 0x9D, 0xDD, 0xDA, 0x78, 0x76, 0x80, 0xB5, 0x8C, 0x05, 0xF4, 0x3D, 0x21,
    0x87, 0x1F, 0xCD, 0x68, 0x23, 0xF6, 0xA8, 0x79, 0xBB, 0x3F, 0x33, 0x95, 0x1C, 0x8E, 0x8E, 0x89,
    0x1D, 0x40, 0x43, 0x88, 0x0B, 0x02, 0xDF, 0xA1, 0xBB, 0x3B, 0xE4, 0x98, 0xB5, 0x0E, 0x75, 0x78,
    0xE6, 0x0D, 0x24, 0x0F, 0x65, 0x85, 0x60, 0x3A, 0x4A, 0xE5, 0x5F, 0x54, 0x9B, 0xC8, 0x79, 0x93,
    0xEB, 0x3D, 0x98, 0x2C, 0xFE, 0x9B, 0xFB, 0x15, 0xB6, 0x88, 0x21, 0x94, 0xB0, 0x05, 0x86, 0x5C,
    0x59, 0x8B, 0x93, 0x7A, 0xDA, 0xD2, 0xA2, 0x14, 0xED, 0xB7, 0xC4, 0x5D, 0xA1, 0xEF, 0x26, 0xF3,
    0xC7, 0x73, 0x29, 0x4D, 0xF1, 0xC8, 0x2C, 0xE0, 0xD0, 0xE9, 0xED, 0x0C, 0x70, 0x75, 0x05, 0x3E,
    0x5B, 0xF6, 0xA0, 0x6E, 0xEA, 0xDE, 0x87, 0x0B, 0x06, 0x29, 0x03, 0xBF, 0xB4, 0x85, 0x9D, 0x04,
    0x75, 0x1A, 0xCD, 0x1E, 0xD6, 0xAA, 0x1B, 0x05, 0x24, 0x6A, 0x2C, 0x80, 0x69, 0x68, 0xDC, 0x97
};


// Stellite (XTL)
const static uint8_t test_output_xtl[160] = {
    0x8F, 0xE5, 0xF0, 0x5F, 0x02, 0x2A, 0x61, 0x7D, 0xE5, 0x3F, 0x79, 0x36, 0x4B, 0x25, 0xCB, 0xC3,
    0xC0, 0x8E, 0x0E, 0x1F, 0xE3, 0xBE, 0x48, 0x57, 0x07, 0x03, 0xFE, 0xE1, 0xEC, 0x0E, 0xB0, 0xB1,
    0x21, 0x26, 0xFF, 0x98, 0xE6, 0x86, 0x08, 0x5B, 0xC9, 0x96, 0x44, 0xA3, 0xB8, 0x4E, 0x28, 0x90,
    0x76, 0xED, 0xAD, 0xB9, 0xAA, 0xAC, 0x01, 0x94, 0x1D, 0xBE, 0x3E, 0xEA, 0xAD, 0xEE, 0xB2, 0xCF,
    0xB0, 0x43, 0x4B, 0x88, 0xFC, 0xB2, 0xF3, 0x82, 0x9D, 0xD7, 0xDF, 0x51, 0x97, 0x2C, 0x5A, 0xE3,
    0xC7, 0x16, 0x0B, 0xC8, 0x7C, 0xB7, 0x2F, 0x1C, 0x55, 0x33, 0xCA, 0xE1, 0xEE, 0x08, 0xA4, 0x86,
    0x60, 0xED, 0x6E, 0x9D, 0x2D, 0x05, 0x0D, 0x7D, 0x02, 0x49, 0x23, 0x39, 0x7C, 0xC3, 0x6D, 0x3D,
    0x05, 0x51, 0x28, 0xF1, 0x9B, 0x3C, 0xDF, 0xC4, 0xEA, 0x8A, 0xA6, 0x6A, 0x3C, 0x8B, 0xE2, 0xAF,
    0x47, 0x00, 0xFC, 0x36, 0xED, 0x50, 0xBB, 0xD2, 0x2E, 0x63, 0x4B, 0x93, 0x11, 0x0C, 0xA7, 0xBA,
    0x32, 0x6E, 0x47, 0x4D, 0xCE, 0xCC, 0x82, 0x54, 0x1D, 0x06, 0xF8, 0x06, 0x86, 0xBD, 0x22, 0x48
};


// Masari (MSR)
const static uint8_t test_output_msr[160] = {
    0x3C, 0x7A, 0x61, 0x08, 0x4C, 0x5E, 0xB8, 0x65, 0xB4, 0x98, 0xAB, 0x2F, 0x5A, 0x1A, 0xC5, 0x2C,
    0x49, 0xC1, 0x77, 0xC2, 0xD0, 0x13, 0x34, 0x42, 0xD6, 0x5E, 0xD5, 0x14, 0x33, 0x5C, 0x82, 0xC5,
    0x69, 0xDF, 0x38, 0x51, 0x1B, 0xB3, 0xEB, 0x7D, 0xE7, 0x6B, 0x08, 0x8E, 0xB6, 0x7E, 0xB7, 0x1C,
    0x5F, 0x3C, 0x81, 0xC9, 0xF7, 0xCE, 0xAE, 0x28, 0xC0, 0xFE, 0xEB, 0xBA, 0x0B, 0x40, 0x38, 0x1D,
    0x44, 0xD0, 0xD5, 0xD3, 0x98, 0x1F, 0xA3, 0x0E, 0xE9, 0x89, 0x1A, 0xD7, 0x88, 0xCC, 0x25, 0x76,
    0x9C, 0xFF, 0x4D, 0x7F, 0x9C, 0xCF, 0x48, 0x07, 0x91, 0xF9, 0x82, 0xF5, 0x4C, 0xE9, 0xBD, 0x82,
    0x36, 0x36, 0x64, 0x14, 0xED, 0xB8, 0x54, 0xEE, 0x22, 0xA1, 0x66, 0xA3, 0x87, 0x10, 0x76, 0x1F,
    0x5A, 0xCD, 0x4C, 0x31, 0x4C, 0xBA, 0x41, 0xD2, 0xDB, 0x6C, 0x31, 0x2E, 0x7A, 0x64, 0x15, 0xFF,
    0xA6, 0xD9, 0xB9, 0x7D, 0x1C, 0x3C, 0x98, 0xDD, 0x16, 0xE6, 0xD3, 0xAA, 0xEF, 0xB6, 0xB3, 0x53,
    0x74, 0xD1, 0xAC, 0x5C, 0x04, 0x26, 0x7D, 0x71, 0xDE, 0xAB, 0x66, 0x28, 0x91, 0x3A, 0x6F, 0x4F
};


// Alloy (XAO)
const static uint8_t test_output_xao[160] = {
    0x9A, 0x29, 0xD0, 0xC4, 0xAF, 0xDC, 0x63, 0x9B, 0x65, 0x53, 0xB1, 0xC8, 0x37, 0x35, 0x11, 0x4C,
    0x5D, 0x77, 0x16, 0x21, 0x42, 0x97, 0x5C, 0xB8, 0x50, 0xC0, 0xA5, 0x1F, 0x64, 0x07, 0xBD, 0x33,
    0xF1, 0xC9, 0x98, 0x40, 0x42, 0xDE, 0x39, 0xD1, 0xBA, 0x2D, 0xAD, 0xEC, 0xFE, 0xEA, 0xD8, 0x46,
    0x56, 0x1C, 0x32, 0x90, 0x42, 0x63, 0x10, 0x80, 0xD7, 0x01, 0xE4, 0xE6, 0x20, 0xB3, 0x60, 0x45,
    0x05, 0xE5, 0xC2, 0x18, 0xCD, 0x07, 0xA4, 0x40, 0x42, 0x91, 0xE2, 0xA4, 0x52, 0x54, 0x79, 0xBA,
    0xCD, 0x7E, 0x61, 0x2D, 0x7F, 0x7E, 0x69, 0x5E, 0xD7, 0xC0, 0x06, 0x65, 0xD7, 0xA1, 0xB8, 0xB8,
    0x1E, 0x31, 0x1C, 0xD3, 0xB7, 0xBC, 0x78, 0x3C, 0x01, 0xAF, 0x77, 0xAA, 0xF3, 0x0F, 0x4C, 0xF2,
    0xD1, 0x8B, 0x58, 0xC7, 0xEB, 0x99, 0x91, 0x53, 0x43, 0x71, 0x47, 0x99, 0x9E, 0x04, 0xA4, 0xEA,
    0xB8, 0xA3, 0xB0, 0x9E, 0x09, 0xF5, 0x57, 0x5C, 0xCF, 0x8A, 0xC6, 0xCA, 0x88, 0x51, 0x9A, 0x01,
    0x31, 0xCC, 0x0C, 0xA6, 0x53, 0xB5, 0x5F, 0xFD, 0x7D, 0x29, 0x3A, 0x35, 0xE9, 0x0E, 0x25, 0x6C
};


// Arto (RTO)
const static uint8_t test_output_rto[160] = {
    0x82, 0x66, 0x1E, 0x1C, 0x6E, 0x64, 0x36, 0x66, 0x84, 0x06, 0x32, 0x7A, 0x9B, 0xB1, 0x13, 0x19,
    0xA5, 0x56, 0x16, 0x15, 0xDF, 0xEC, 0x1C, 0x9E, 0xE3, 0x88, 0x4A, 0x6C, 0x1C, 0xEB, 0x76, 0xA5,
    0xB3, 0xFB, 0xF4, 0x3F, 0x2B, 0x6A, 0x3A, 0x39, 0xA3, 0x6E, 0x08, 0x33, 0x67, 0x90, 0x31, 0xB9,
    0x3F, 0x27, 0xE4, 0x79, 0x32, 0x61, 0x6B, 0x5C, 0x8A, 0xF8, 0xAF, 0xC0, 0x60, 0xFD, 0x83, 0xB7,
    0x11, 0x11, 0x89, 0xB4, 0xDC, 0xAE, 0x40, 0xC8, 0x64, 0xAA, 0x4D, 0x19, 0x23, 0x7B, 0xD3, 0x27,
    0xB2, 0x0F, 0xA7, 0x50, 0x7D, 0xCA, 0xF5, 0x03, 0x06, 0xB2, 0x26, 0x62, 0xF3, 0x68, 0x2D, 0x30,
    0x6F, 0x93, 0x1E, 0xFF, 0xCD, 0x85, 0x40, 0x28, 0x5F, 0xC3, 0x8C, 0x76, 0x51, 0x9E, 0xD5, 0x06,
    0x32, 0xD6, 0x35, 0x83, 0xF6, 0x3B, 0x54, 0x4F, 0xA1, 0x9C, 0x13, 0xD8, 0xC4, 0x0E, 0x01, 0x2F,
    0x29, 0xDB, 0x8C, 0x1C, 0xB7, 0x06, 0x86, 0x79, 0x6D, 0xFF, 0x9F, 0x89, 0x3B, 0x3A, 0xA5, 0x79,
    0xE7, 0x81, 0x4E, 0x2A, 0xBD, 0x62, 0xC1, 0x1B, 0x7C, 0xB9, 0x33, 0x7B, 0xEE, 0x95, 0x80, 0xB3
};


#ifndef XMRIG_NO_AEON
const static uint8_t test_output_v0_lite[160] = {
    0x36, 0x95, 0xB4, 0xB5, 0x3B, 0xB0, 0x03, 0x58, 0xB0, 0xAD, 0x38, 0xDC, 0x16, 0x0F, 0xEB, 0x9E,
    0x00, 0x4E, 0xEC, 0xE0, 0x9B, 0x83, 0xA7, 0x2E, 0xF6, 0xBA, 0x98, 0x64, 0xD3, 0x51, 0x0C, 0x88,
    0x28, 0xA2, 0x2B, 0xAD, 0x3F, 0x93, 0xD1, 0x40, 0x8F, 0xCA, 0x47, 0x2E, 0xB5, 0xAD, 0x1C, 0xBE,
    0x75, 0xF2, 0x1D, 0x05, 0x3C, 0x8C, 0xE5, 0xB3, 0xAF, 0x10, 0x5A, 0x57, 0x71, 0x3E, 0x21, 0xDD,
    0x38, 0x08, 0xE1, 0x17, 0x0B, 0x99, 0x8D, 0x1A, 0x3C, 0xCE, 0x35, 0xC5, 0xC7, 0x3A, 0x00, 0x2E,
    0xCB, 0x54, 0xF0, 0x78, 0x2E, 0x9E, 0xDB, 0xC7, 0xDF, 0x2E, 0x71, 0x9A, 0x16, 0x97, 0xC4, 0x18,
    0x4B, 0x97, 0x07, 0xFE, 0x5D, 0x98, 0x9A, 0xD6, 0xD8, 0xE5, 0x92, 0x66, 0x87, 0x7F, 0x19, 0x37,
    0xA2, 0x5E, 0xE6, 0x96, 0xB5, 0x97, 0x33, 0x89, 0xE0, 0xA7, 0xC9, 0xDD, 0x4A, 0x7E, 0x9E, 0x53,
    0xBE, 0x91, 0x2B, 0xF5, 0xF5, 0xAF, 0xDD, 0x09, 0xA2, 0xF4, 0xA4, 0x56, 0xEB, 0x96, 0x22, 0xC9,
    0x94, 0xFB, 0x7B, 0x28, 0xC9, 0x97, 0x65, 0x04, 0xAC, 0x4F, 0x84, 0x71, 0xDA, 0x6E, 0xD8, 0xC5
};


// AEON v7
const static uint8_t test_output_v1_lite[160] = {
    0x6D, 0x8C, 0xDC, 0x44, 0x4E, 0x9B, 0xBB, 0xFD, 0x68, 0xFC, 0x43, 0xFC, 0xD4, 0x85, 0x5B, 0x22,
    0x8C, 0x8A, 0x1B, 0xD9, 0x1D, 0x9D, 0x00, 0x28, 0x5B, 0xEC, 0x02, 0xB7, 0xCA, 0x2D, 0x67, 0x41,
    0x87, 0xC4, 0xE5, 0x70, 0x65, 0x3E, 0xB4, 0xC2, 0xB4, 0x2B, 0x7A, 0x0D, 0x54, 0x65, 0x59, 0x45,
    0x2D, 0xFA, 0xB5, 0x73, 0xB8, 0x2E, 0xC5, 0x2F, 0x15, 0x2B, 0x7F, 0xF9, 0x8E, 0x79, 0x44, 0x6F,
    0x16, 0x08, 0x74, 0xC7, 0xA2, 0xD2, 0xA3, 0x97, 0x95, 0x76, 0xCA, 0x4D, 0x06, 0x39, 0x7A, 0xAB,
    0x6C, 0x87, 0x58, 0x33, 0x4D, 0xC8, 0x5A, 0xAB, 0x04, 0x27, 0xFE, 0x8B, 0x1C, 0x23, 0x2F, 0x32,
    0xC0, 0x44, 0xFF, 0x0D, 0xB5, 0x3B, 0x27, 0x96, 0x06, 0x89, 0x7B, 0xA3, 0x0B, 0xD0, 0xCE, 0x9E,
    0x90, 0x22, 0x77, 0x5A, 0xAD, 0xA1, 0xE5, 0xB6, 0xFC, 0xCB, 0x39, 0x7E, 0x2B, 0x10, 0xEE, 0xB4,
    0x8C, 0x2B, 0xA4, 0x1F, 0x60, 0x76, 0x39, 0xD7, 0xF6, 0x46, 0x77, 0x18, 0x20, 0xAD, 0xD4, 0xC9,
    0x87, 0xF7, 0x37, 0xDA, 0xFD, 0xBA, 0xBA, 0xD2, 0xF2, 0x68, 0xDC, 0x26, 0x8D, 0x1B, 0x08, 0xC6
};
#endif


#ifndef XMRIG_NO_SUMO
const static uint8_t test_output_v0_heavy[160] = {
    0x99, 0x83, 0xF2, 0x1B, 0xDF, 0x20, 0x10, 0xA8, 0xD7, 0x07, 0xBB, 0x2F, 0x14, 0xD7, 0x86, 0x64,
    0xBB, 0xE1, 0x18, 0x7F, 0x55, 0x01, 0x4B, 0x39, 0xE5, 0xF3, 0xD6, 0x93, 0x28, 0xE4, 0x8F, 0xC2,
    0x4D, 0x94, 0x7D, 0xD6, 0xDB, 0x6E, 0x07, 0x48, 0x26, 0x4A, 0x51, 0x2E, 0xAC, 0xF3, 0x25, 0x4A,
    0x1F, 0x1A, 0xA2, 0x5B, 0xFC, 0x0A, 0xAD, 0x82, 0xDE, 0xA8, 0x99, 0x96, 0x88, 0x52, 0xD2, 0x7D,
    0x3E, 0xE1, 0x23, 0x03, 0x5A, 0x63, 0x7B, 0x66, 0xF6, 0xD7, 0xC2, 0x2A, 0x34, 0x5E, 0x88, 0xE7,
    0xFA, 0xC4, 0x25, 0x36, 0x54, 0xCB, 0xD2, 0x5C, 0x2F, 0x80, 0x2A, 0xF9, 0xCC, 0x43, 0xF7, 0xCD,
    0xE5, 0x18, 0xA8, 0x05, 0x60, 0x18, 0xA5, 0x73, 0x72, 0x9B, 0x32, 0xDC, 0x69, 0x83, 0xC1, 0xE1,
    0x1F, 0xDB, 0xDA, 0x6B, 0xAC, 0xEC, 0x9F, 0x67, 0xF8, 0x27, 0x1D, 0xC7, 0xE6, 0x46, 0x42, 0xF9,
    0x53, 0x62, 0x0A, 0x54, 0x7D, 0x43, 0xEA, 0x18, 0x94, 0xED, 0xD8, 0x92, 0x06, 0x6A, 0xA1, 0x51,
    0xAD, 0xB1, 0xFD, 0x89, 0xFB, 0x5C, 0xB4, 0x25, 0x6A, 0xDD, 0xB0, 0x09, 0xC5, 0x72, 0x87, 0xEB
};

const static uint8_t test_output_xhv_heavy[160] = {
    0x5A, 0xC3, 0xF7, 0x85, 0xC4, 0x90, 0xC5, 0x85, 0x50, 0xEC, 0x95, 0xD2, 0x72, 0x65, 0x63, 0x57,
    0x7E, 0x7C, 0x1C, 0x21, 0x2D, 0x0C, 0xDE, 0x59, 0x12, 0x73, 0x20, 0x1E, 0x44, 0xFD, 0xD5, 0xB6,
    0x1F, 0x4E, 0xB2, 0x0A, 0x36, 0x51, 0x4B, 0xF5, 0x4D, 0xC9, 0xE0, 0x90, 0x2C, 0x16, 0x47, 0x3F,
    0xDE, 0x18, 0x29, 0x8E, 0xBB, 0x34, 0x2B, 0xEF, 0x7A, 0x04, 0x22, 0xD1, 0xB1, 0xF2, 0x48, 0xDA,
    0xE3, 0x7F, 0x4B, 0x4C, 0xB4, 0xDF, 0xE8, 0xD3, 0x70, 0xE2, 0xE7, 0x44, 0x25, 0x87, 0x12, 0xF9,
    0x8F, 0x28, 0x0B, 0xCE, 0x2C, 0xEE, 0xDD, 0x88, 0x94, 0x35, 0x48, 0x51, 0xAE, 0xC8, 0x9C, 0x0B,
    0xED, 0x2F, 0xE6, 0x0F, 0x39, 0x05, 0xB4, 0x4A, 0x8F, 0x38, 0x44, 0x2D, 0x4B, 0xE9, 0x7B, 0x81,
    0xC6, 0xB0, 0xE0, 0x0A, 0x39, 0x8C, 0x38, 0xFE, 0x63, 0x31, 0x47, 0x65, 0x0D, 0x2B, 0xF4, 0x96,
    0x13, 0x91, 0x89, 0xB4, 0x5B, 0xA9, 0x2A, 0x7A, 0x09, 0x65, 0x14, 0x20, 0x76, 0x24, 0x6C, 0x80,
    0x1D, 0x3F, 0x9F, 0xCD, 0x68, 0x39, 0xA9, 0x42, 0x27, 0xC1, 0x0C, 0x53, 0x98, 0x35, 0x60, 0x7A
};


// TUBE
const static uint8_t test_output_tube_heavy[160] = {
    0xFE, 0x53, 0x35, 0x20, 0x76, 0xEA, 0xE6, 0x89, 0xFA, 0x3B, 0x4F, 0xDA, 0x61, 0x46, 0x34, 0xCF,
    0xC3, 0x12, 0xEE, 0x0C, 0x38, 0x7D, 0xF2, 0xB8, 0xB7, 0x4D, 0xA2, 0xA1, 0x59, 0x74, 0x12, 0x35,
    0xCD, 0x3F, 0x29, 0xDF, 0x07, 0x4A, 0x14, 0xAD, 0x0B, 0x98, 0x99, 0x37, 0xCA, 0x14, 0x68, 0xA3,
    0x8D, 0xAE, 0x86, 0xC1, 0xA3, 0x54, 0x05, 0xBE, 0xEA, 0x6D, 0x29, 0x24, 0x0C, 0x82, 0x97, 0x74,
    0xA0, 0x64, 0x77, 0xCD, 0x8D, 0x8A, 0xC3, 0x10, 0xB4, 0x89, 0x0E, 0xBB, 0x7D, 0xE6, 0x32, 0x8F,
    0xF4, 0x2D, 0xB6, 0x9E, 0x8A, 0xF9, 0xF8, 0xEE, 0x2C, 0xD0, 0x74, 0xED, 0xA9, 0xAA, 0xA1, 0xFB,
    0xE2, 0xC9, 0x89, 0x66, 0xD6, 0x66, 0x52, 0xA2, 0x16, 0xDA, 0x36, 0xA0, 0x10, 0x62, 0xD2, 0xB1,
    0x76, 0xD1, 0x31, 0xE9, 0x1C, 0x08, 0xB6, 0xCA, 0xAF, 0x89, 0xB9, 0x3D, 0x2C, 0xFA, 0x9A, 0x30,
    0x74, 0x6A, 0x96, 0xA1, 0x95, 0x6C, 0xBB, 0x46, 0x4D, 0xE0, 0xEB, 0x28, 0xBE, 0x2A, 0x8C, 0x34,
    0x57, 0x79, 0xBE, 0x52, 0xFB, 0xBC, 0x68, 0x43, 0x45, 0xF4, 0xDF, 0xA5, 0xA8, 0xFD, 0x55, 0xA6
};
#endif


unsigned char hf_hex2bin(char c, bool &err);
char hf_bin2hex(unsigned char c);

#endif /* __CRYPTONIGHT_TEST_H__ */
