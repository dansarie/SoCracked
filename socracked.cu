/* socracked.cu

   CUDA bitslice implementation of attacks on SoCracked.

   Copyright (C) 2017-2018 Marcus Dansarie <marcus@dansarie.se>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program. If not, see <http://www.gnu.org/licenses/>. */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include <cuda_profiler_api.h>

#include "sodark.h"
#include "socracked.h"
#include "socracked_cuda.h"

typedef struct {
  int b0;
  int b1;
  int b2;
  int b3;
  int b4;
  int b5;
  int b6;
  int b7;
} eightbits;

typedef struct {
  eightbits a;
  eightbits b;
  eightbits c;
} twentyfourbits;

/* Device constant memory. */

__constant__ int pt1_c[24];
__constant__ int pt2_c[24];
__constant__ int ct1_c[24];
__constant__ int tw1_c[64];
__constant__ int tw2_c[64];
__constant__ int key_c[24];
__constant__ int key3_c[256];

/* Device functions */

/* Macro for using the CUDA lop3.b32 instruction.
   a - output variable
   b - input 1
   c - input 2
   d - input 3
   e - lookup table. */
#define LUT(a,b,c,d,e) asm("lop3.b32 %0, %1, %2, %3, "#e";" : "=r"(a): "r"(b), "r"(c), "r"(d));

/* The functions s0 to s7 calculate one output bit each of the SoDark S-box. */

__device__ __forceinline__ int s0(eightbits in) {
  int var8;  LUT(var8, in.b6, in.b3, in.b4, 0x5e);
  int var9 = var8 | in.b5;
  int var10; LUT(var10, in.b5, in.b4, in.b6, 0x8e);
  int var11; LUT(var11, in.b1, var9, var10, 0xac);
  int var12; LUT(var12, in.b3, in.b6, var10, 0x68);
  int var13; LUT(var13, in.b1, in.b4, var11, 0x8f);
  int var14; LUT(var14, var13, var12, in.b5, 0xca);
  int var15; LUT(var15, in.b2, var11, var14, 0xac);
  int var16; LUT(var16, in.b2, in.b4, var13, 0x7c);
  int var17; LUT(var17, in.b1, in.b6, var14, 0x7a);
  int var18; LUT(var18, var17, var16, var9, 0x96);
  int var19; LUT(var19, in.b2, var12, var18, 0x09);
  int var20; LUT(var20, in.b1, in.b4, in.b5, 0x25);
  int var21; LUT(var21, var20, var19, in.b6, 0xed);
  int var22; LUT(var22, in.b3, var18, var21, 0xac);
  int var23; LUT(var23, in.b7, var15, var22, 0xac);
  int var24; LUT(var24, in.b3, var16, var20, 0x63);
  int var25; LUT(var25, var24, var12, var15, 0x09);
  int var26; LUT(var26, in.b4, var25, var21, 0x71);
  int var27; LUT(var27, in.b6, var25, var26, 0xac);
  int var28; LUT(var28, in.b5, in.b6, var25, 0x6b);
  int var29; LUT(var29, var28, var8, var14, 0x58);
  int var30; LUT(var30, in.b1, var27, var29, 0xac);
  int var31; LUT(var31, in.b2, var23, var24, 0x4e);
  int var32; LUT(var32, var31, var17, var21, 0x92);
  int var33; LUT(var33, in.b2, var10, var30, 0x42);
  int var34; LUT(var34, var33, var13, var19, 0x41);
  int var35; LUT(var35, in.b6, var32, var34, 0xac);
  int var36; LUT(var36, in.b7, var30, var35, 0xac);
  int out0;  LUT(out0, in.b0, var23, var36, 0xac);
  return out0;
}

__device__ __forceinline__ int s1(eightbits in) {
  int var8;  LUT(var8, in.b4, in.b5, in.b6, 0x76);
  int var9;  LUT(var9, in.b5, in.b6, in.b7, 0xef);
  int var10; LUT(var10, in.b4, var8, var9, 0xac);
  int var11; LUT(var11, in.b4, in.b5, in.b6, 0x18);
  int var12; LUT(var12, var11, in.b7, var8, 0xa9);
  int var13; LUT(var13, in.b3, var10, var12, 0xac);
  int var14; LUT(var14, in.b7, var9, var12, 0x86);
  int var15; LUT(var15, in.b3, in.b4, var13, 0xe3);
  int var16; LUT(var16, var15, var14, var11, 0x8b);
  int var17; LUT(var17, in.b1, var13, var16, 0xac);
  int var18; LUT(var18, in.b4, in.b6, var17, 0x49);
  int var19; LUT(var19, in.b3, in.b7, var11, 0x36);
  int var20; LUT(var20, var19, var18, var14, 0xbc);
  int var21; LUT(var21, in.b6, var15, var20, 0x96);
  int var22; LUT(var22, in.b3, var11, var13, 0x29);
  int var23; LUT(var23, var22, var21, var14, 0x9e);
  int var24; LUT(var24, in.b1, var20, var23, 0xac);
  int var25; LUT(var25, in.b2, var17, var24, 0xac);
  int var26; LUT(var26, in.b3, in.b6, var24, 0x7a);
  int var27; LUT(var27, in.b1, var9, var21, 0x60);
  int var28; LUT(var28, var27, var26, var16, 0x1c);
  int var29; LUT(var29, in.b1, var8, var28, 0x97);
  int var30; LUT(var30, var29, in.b6, var23, 0xd6);
  int var31; LUT(var31, in.b4, var28, var30, 0xac);
  int var32; LUT(var32, var21, var24, var29, 0xc5);
  int var33; LUT(var33, var12, var15, var19, 0x78);
  int var34; LUT(var34, var33, var32, in.b7, 0xd6);
  int var35; LUT(var35, var10, var14, var18, 0x7a);
  int var36; LUT(var36, var35, in.b3, var29, 0x87);
  int var37; LUT(var37, in.b1, var34, var36, 0xac);
  int var38; LUT(var38, in.b2, var31, var37, 0xac);
  int out1;  LUT(out1, in.b0, var25, var38, 0xac);
  return out1;
}

__device__ __forceinline__ int s2(eightbits in) {
  int var8;  LUT(var8, in.b5, in.b7, in.b6, 0xe5);
  int var9;  LUT(var9, in.b6, in.b7, in.b5, 0xc7);
  int var10; LUT(var10, in.b3, var8, var9, 0xac);
  int var11; LUT(var11, in.b3, in.b6, in.b7, 0x2c);
  int var12; LUT(var12, var11, var8, var9, 0xe3);
  int var13; LUT(var13, in.b0, var10, var12, 0xac);
  int var14; LUT(var14, in.b6, var10, var13, 0xa7);
  int var15; LUT(var15, in.b0, in.b3, var9, 0x86);
  int var16; LUT(var16, var15, var14, in.b7, 0x5c);
  int var17; LUT(var17, in.b4, var13, var16, 0xac);
  int var18; LUT(var18, in.b7, var15, var17, 0xd6);
  int var19; LUT(var19, in.b4, in.b5, var9, 0xd4);
  int var20; LUT(var20, var19, var18, var16, 0xd3);
  int var21; LUT(var21, in.b4, var16, var20, 0x8e);
  int var22; LUT(var22, var21, in.b3, var19, 0x69);
  int var23; LUT(var23, in.b0, var20, var22, 0xac);
  int var24; LUT(var24, in.b1, var17, var23, 0xac);
  int var25; LUT(var25, in.b6, var8, var21, 0x38);
  int var26; LUT(var26, in.b4, var11, var22, 0x97);
  int var27; LUT(var27, var26, var25, var20, 0xc2);
  int var28; LUT(var28, var11, var21, var24, 0xa6);
  int var29; LUT(var29, var10, var22, var25, 0x6f);
  int var30; LUT(var30, var29, var28, in.b7, 0x38);
  int var31; LUT(var31, in.b0, var27, var30, 0xac);
  int var32; LUT(var32, var10, var14, var25, 0x58);
  int var33; LUT(var33, var32, var26, var30, 0xb4);
  int var34; LUT(var34, in.b7, var8, var24, 0x3a);
  int var35; LUT(var35, in.b5, var9, var33, 0x52);
  int var36; LUT(var36, var35, var34, in.b4, 0x79);
  int var37; LUT(var37, in.b0, var33, var36, 0xac);
  int var38; LUT(var38, in.b1, var31, var37, 0xac);
  int out2;  LUT(out2, in.b2, var24, var38, 0xac);
  return out2;
}

__device__ __forceinline__ int s3(eightbits in) {
  int var8;  LUT(var8, in.b3, in.b2, in.b1, 0x85);
  int var9;  LUT(var9, in.b4, var8, in.b5, 0xac);
  int var10; LUT(var10, in.b2, in.b3, in.b4, 0xad);
  int var11; LUT(var11, var10, in.b1, var8, 0x9c);
  int var12; LUT(var12, in.b5, var9, var11, 0xac);
  int var13; LUT(var13, in.b5, var10, var11, 0xd9);
  int var14; LUT(var14, in.b4, var8, var12, 0x14);
  int var15; LUT(var15, var14, var13, in.b2, 0xa6);
  int var16; LUT(var16, in.b7, var12, var15, 0xac);
  int var17; LUT(var17, in.b5, var14, var16, 0x1a);
  int var18; LUT(var18, in.b4, in.b7, var10, 0x75);
  int var19; LUT(var19, var18, var17, var15, 0x25);
  int var20; LUT(var20, var9, var10, var15, 0xe6);
  int var21; LUT(var21, in.b1, in.b2, in.b5, 0x6d);
  int var22; LUT(var22, var21, var20, in.b7, 0xb4);
  int var23; LUT(var23, in.b3, var19, var22, 0xac);
  int var24; LUT(var24, in.b6, var16, var23, 0xac);
  int var25; LUT(var25, in.b6, var18, var21, 0x18);
  int var26; LUT(var26, in.b2, in.b5, var11, 0xe1);
  int var27; LUT(var27, var26, var25, var23, 0xde);
  int var28; LUT(var28, var8, var13, var24, 0xd4);
  int var29; LUT(var29, in.b6, var10, var22, 0xc4);
  int var30; LUT(var30, var29, var28, var14, 0x96);
  int var31; LUT(var31, in.b1, var27, var30, 0xac);
  int var32; LUT(var32, var17, var21, var31, 0x5b);
  int var33; LUT(var33, var32, in.b5, var29, 0x61);
  int var34; LUT(var34, var19, var31, var33, 0x92);
  int var35; LUT(var35, in.b4, in.b5, var25, 0x5c);
  int var36; LUT(var36, var35, var34, var27, 0x68);
  int var37; LUT(var37, in.b3, var33, var36, 0xac);
  int var38; LUT(var38, in.b7, var31, var37, 0xac);
  int out3;  LUT(out3, in.b0, var24, var38, 0xac);
  return out3;
}

__device__ __forceinline__ int s4(eightbits in) {
  int var8;  LUT(var8, in.b2, in.b5, in.b1, 0xe3);
  int var9;  LUT(var9, var8, in.b1, in.b7, 0xbe);
  int var10; LUT(var10, in.b0, var8, var9, 0xac);
  int var11; LUT(var11, var9, in.b1, in.b2, 0x49);
  int var12; LUT(var12, in.b4, var10, var11, 0xac);
  int var13; LUT(var13, var8, var9, var12, 0x6f);
  int var14; LUT(var14, in.b0, in.b4, in.b7, 0x71);
  int var15; LUT(var15, var14, var13, in.b2, 0x68);
  int var16; LUT(var16, in.b6, var12, var15, 0xac);
  int var17; LUT(var17, in.b4, in.b6, var13, 0x68);
  int var18; LUT(var18, in.b0, in.b1, var16, 0x27);
  int var19; LUT(var19, var18, var17, var15, 0x79);
  int var20; LUT(var20, var14, var18, var19, 0xf6);
  int var21; LUT(var21, in.b0, in.b1, var13, 0x92);
  int var22; LUT(var22, var21, var20, in.b6, 0x69);
  int var23; LUT(var23, in.b7, var19, var22, 0xac);
  int var24; LUT(var24, in.b3, var16, var23, 0xac);
  int var25; LUT(var25, in.b7, var19, var22, 0x26);
  int var26; LUT(var26, in.b1, in.b6, var15, 0xd1);
  int var27; LUT(var27, var26, var25, var17, 0x9c);
  int var28; LUT(var28, var12, var18, var20, 0xe0);
  int var29; LUT(var29, var10, var22, var23, 0x29);
  int var30; LUT(var30, var29, var28, in.b4, 0x96);
  int var31; LUT(var31, in.b3, var27, var30, 0xac);
  int var32; LUT(var32, in.b6, var24, var28, 0x56);
  int var33; LUT(var33, var32, in.b1, in.b3, 0x79);
  int var34; LUT(var34, var21, var30, var33, 0x84);
  int var35; LUT(var35, in.b1, in.b7, var32, 0xa9);
  int var36; LUT(var36, var35, var34, in.b6, 0x9a);
  int var37; LUT(var37, in.b0, var33, var36, 0xac);
  int var38; LUT(var38, in.b2, var31, var37, 0xac);
  int out4;  LUT(out4, in.b5, var24, var38, 0xac);
  return out4;
}

__device__ __forceinline__ int s5(eightbits in) {
  int var8;  LUT(var8, in.b7, in.b5, in.b2, 0xa8);
  int var9;  LUT(var9, in.b5, in.b3, in.b2, 0x3d);
  int var10; LUT(var10, in.b0, var8, var9, 0xac);
  int var11; LUT(var11, in.b0, in.b3, in.b5, 0xd3);
  int var12; LUT(var12, var11, var8, var9, 0x92);
  int var13; LUT(var13, in.b1, var10, var12, 0xac);
  int var14; LUT(var14, in.b3, var8, var11, 0x86);
  int var15; LUT(var15, in.b1, var9, var12, 0x14);
  int var16; LUT(var16, var15, var14, var13, 0x79);
  int var17; LUT(var17, in.b7, var13, var16, 0xac);
  int var18; LUT(var18, in.b0, in.b5, var12, 0x5a);
  int var19; LUT(var19, var18, in.b7, var9, 0x94);
  int var20; LUT(var20, in.b7, var12, var19, 0x61);
  int var21; LUT(var21, in.b2, in.b3, var9, 0xb5);
  int var22; LUT(var22, var21, var20, in.b5, 0x97);
  int var23; LUT(var23, in.b1, var19, var22, 0xac);
  int var24; LUT(var24, in.b4, var17, var23, 0xac);
  int var25; LUT(var25, in.b3, in.b4, in.b5, 0x0d);
  int var26; LUT(var26, var25, var18, var24, 0x38);
  int var27; LUT(var27, var9, var20, var26, 0x8e);
  int var28; LUT(var28, in.b4, var10, var19, 0x1a);
  int var29; LUT(var29, var28, var27, var24, 0xa9);
  int var30; LUT(var30, in.b1, var26, var29, 0xac);
  int var31; LUT(var31, in.b7, var22, var28, 0x35);
  int var32; LUT(var32, var31, var21, var24, 0x85);
  int var33; LUT(var33, in.b5, in.b7, var19, 0xa0);
  int var34; LUT(var34, in.b3, var28, var31, 0x3d);
  int var35; LUT(var35, var34, var33, var32, 0x96);
  int var36; LUT(var36, in.b1, var32, var35, 0xac);
  int var37; LUT(var37, in.b2, var30, var36, 0xac);
  int out5;  LUT(out5, in.b6, var24, var37, 0xac);
  return out5;
}

__device__ __forceinline__ int s6(eightbits in) {
  int var8;  LUT(var8, in.b1, in.b2, in.b6, 0x61);
  int var9;  LUT(var9, in.b7, in.b6, var8, 0xac);
  int var10; LUT(var10, in.b2, in.b7, var8, 0x76);
  int var11; LUT(var11, var10, in.b1, in.b6, 0x24);
  int var12; LUT(var12, in.b5, var9, var11, 0xac);
  int var13; LUT(var13, in.b6, in.b7, var8, 0xfc);
  int var14; LUT(var14, in.b1, in.b2, in.b5, 0x5b);
  int var15; LUT(var15, var14, var13, var12, 0x59);
  int var16; LUT(var16, in.b0, var12, var15, 0xac);
  int var17; LUT(var17, var8, var15, var16, 0x73);
  int var18; LUT(var18, var17, in.b6, in.b7, 0x8b);
  int var19; LUT(var19, in.b1, in.b6, var18, 0xe8);
  int var20; LUT(var20, in.b0, in.b2, var11, 0x49);
  int var21; LUT(var21, var20, var19, var10, 0xa7);
  int var22; LUT(var22, in.b5, var18, var21, 0xac);
  int var23; LUT(var23, in.b4, var16, var22, 0xac);
  int var24; LUT(var24, in.b0, in.b5, var18, 0x5b);
  int var25; LUT(var25, var24, var8, var14, 0x29);
  int var26; LUT(var26, in.b5, var8, var13, 0x4a);
  int var27; LUT(var27, in.b0, in.b7, var12, 0x7e);
  int var28; LUT(var28, var27, var26, var18, 0x69);
  int var29; LUT(var29, in.b2, var25, var28, 0xac);
  int var30; LUT(var30, in.b6, in.b7, var8, 0x4f);
  int var31; LUT(var31, var30, in.b5, var10, 0x69);
  int var32; LUT(var32, var14, var26, var28, 0xa4);
  int var33; LUT(var33, in.b1, in.b6, var29, 0x98);
  int var34; LUT(var34, var33, var32, var13, 0x39);
  int var35; LUT(var35, in.b0, var31, var34, 0xac);
  int var36; LUT(var36, in.b4, var29, var35, 0xac);
  int out6;  LUT(out6, in.b3, var23, var36, 0xac);
  return out6;
}

__device__ __forceinline__ int s7(eightbits in) {
  int var8;  LUT(var8, in.b1, in.b0, in.b2, 0x6f);
  int var9;  LUT(var9, in.b6, var8, in.b2, 0xac);
  int var10; LUT(var10, in.b0, in.b1, in.b2, 0x5c);
  int var11; LUT(var11, var10, in.b6, var9, 0x86);
  int var12; LUT(var12, in.b3, var9, var11, 0xac);
  int var13; LUT(var13, in.b2, in.b3, var9, 0x7b);
  int var14; LUT(var14, in.b0, in.b6, var12, 0x19);
  int var15; LUT(var15, var14, var13, var8, 0xb6);
  int var16; LUT(var16, in.b4, var12, var15, 0xac);
  int var17; LUT(var17, in.b2, in.b6, var15, 0x72);
  int var18; LUT(var18, in.b0, in.b1, in.b3, 0xa9);
  int var19; LUT(var19, var18, var17, var14, 0x36);
  int var20; LUT(var20, in.b6, var10, var18, 0xd6);
  int var21; LUT(var21, in.b1, var12, var13, 0x46);
  int var22; LUT(var22, var21, var20, var17, 0xcb);
  int var23; LUT(var23, in.b4, var19, var22, 0xac);
  int var24; LUT(var24, in.b7, var16, var23, 0xac);
  int var25; LUT(var25, in.b7, var19, var20, 0x79);
  int var26; LUT(var26, in.b3, var11, var17, 0x3e);
  int var27; LUT(var27, var26, var25, var9, 0x6a);
  int var28; LUT(var28, in.b7, var9, var13, 0x4d);
  int var29; LUT(var29, var28, in.b3, var20, 0x96);
  int var30; LUT(var30, in.b4, var27, var29, 0xac);
  int var31; LUT(var31, var16, var27, var29, 0xf2);
  int var32; LUT(var32, in.b3, in.b7, var23, 0xe6);
  int var33; LUT(var33, var32, var31, var13, 0x92);
  int var34; LUT(var34, in.b7, var16, var29, 0xd4);
  int var35; LUT(var35, var34, var22, var30, 0x16);
  int var36; LUT(var36, in.b6, var33, var35, 0xac);
  int var37; LUT(var37, in.b1, var30, var36, 0xac);
  int out7;  LUT(out7, in.b5, var24, var37, 0xac);
  return out7;
}

/* Bitsliced single round encryption. Used by the brute force search algorithm
   in an unrolled loop. */
template <bool last>
__device__ __forceinline__ twentyfourbits encrypt_round(twentyfourbits bits, int round,
    volatile const int * __restrict key_hi) {

  volatile int bidx = blockIdx.x;
  volatile int tidx = threadIdx.x;

  eightbits cur;

  /* Calculate round tweak offsets. */
  int tw_off_a, tw_off_b, tw_off_c;
  switch (round % 8) {
    case 0:
      tw_off_a = 16;
      tw_off_c = 8;
      tw_off_b = 0;
      break;
    case 1:
      tw_off_a = 56;
      tw_off_c = 48;
      tw_off_b = 40;
      break;
    case 2:
      tw_off_a = 32;
      tw_off_c = 24;
      tw_off_b = 16;
      break;
    case 3:
      tw_off_a = 8;
      tw_off_c = 0;
      tw_off_b = 56;
      break;
    case 4:
      tw_off_a = 48;
      tw_off_c = 40;
      tw_off_b = 32;
      break;
    case 5:
      tw_off_a = 24;
      tw_off_c = 16;
      tw_off_b = 8;
      break;
    case 6:
      tw_off_a = 0;
      tw_off_c = 56;
      tw_off_b = 48;
      break;
    case 7:
      tw_off_a = 40;
      tw_off_c = 32;
      tw_off_b = 24;
      break;
  }

  /* A xor B xor key xor tweak. */
  switch (round % 7) {
    case 0:
      cur.b7 = (0 - ((bidx >> 8)  & 1)) ^ tw1_c[tw_off_a + 7] ^ bits.b.b7 ^ bits.a.b7;
      cur.b6 = (0 - ((bidx >> 7)  & 1)) ^ tw1_c[tw_off_a + 6] ^ bits.b.b6 ^ bits.a.b6;
      cur.b5 = (0 - ((bidx >> 6)  & 1)) ^ tw1_c[tw_off_a + 5] ^ bits.b.b5 ^ bits.a.b5;
      cur.b4 = (0 - ((bidx >> 5)  & 1)) ^ tw1_c[tw_off_a + 4] ^ bits.b.b4 ^ bits.a.b4;
      cur.b3 = (0 - ((bidx >> 4)  & 1)) ^ tw1_c[tw_off_a + 3] ^ bits.b.b3 ^ bits.a.b3;
      cur.b2 = (0 - ((bidx >> 3)  & 1)) ^ tw1_c[tw_off_a + 2] ^ bits.b.b2 ^ bits.a.b2;
      cur.b1 = (0 - ((bidx >> 2)  & 1)) ^ tw1_c[tw_off_a + 1] ^ bits.b.b1 ^ bits.a.b1;
      cur.b0 = (0 - ((bidx >> 1)  & 1)) ^ tw1_c[tw_off_a]     ^ bits.b.b0 ^ bits.a.b0;
      break;
    case 1:
      cur.b7 = key_hi[23]               ^ tw1_c[tw_off_a + 7] ^ bits.b.b7 ^ bits.a.b7;
      cur.b6 = key_hi[22]               ^ tw1_c[tw_off_a + 6] ^ bits.b.b6 ^ bits.a.b6;
      cur.b5 = key_hi[21]               ^ tw1_c[tw_off_a + 5] ^ bits.b.b5 ^ bits.a.b5;
      cur.b4 = key_hi[20]               ^ tw1_c[tw_off_a + 4] ^ bits.b.b4 ^ bits.a.b4;
      cur.b3 = key_hi[19]               ^ tw1_c[tw_off_a + 3] ^ bits.b.b3 ^ bits.a.b3;
      cur.b2 = key_hi[18]               ^ tw1_c[tw_off_a + 2] ^ bits.b.b2 ^ bits.a.b2;
      cur.b1 = key_hi[17]               ^ tw1_c[tw_off_a + 1] ^ bits.b.b1 ^ bits.a.b1;
      cur.b0 = key_hi[16]               ^ tw1_c[tw_off_a]     ^ bits.b.b0 ^ bits.a.b0;
      break;
    case 2:
      cur.b7 = (0 - ((bidx >> 16) & 1)) ^ tw1_c[tw_off_a + 7] ^ bits.b.b7 ^ bits.a.b7;
      cur.b6 = (0 - ((bidx >> 15) & 1)) ^ tw1_c[tw_off_a + 6] ^ bits.b.b6 ^ bits.a.b6;
      cur.b5 = (0 - ((bidx >> 14) & 1)) ^ tw1_c[tw_off_a + 5] ^ bits.b.b5 ^ bits.a.b5;
      cur.b4 = (0 - ((bidx >> 13) & 1)) ^ tw1_c[tw_off_a + 4] ^ bits.b.b4 ^ bits.a.b4;
      cur.b3 = (0 - ((bidx >> 12) & 1)) ^ tw1_c[tw_off_a + 3] ^ bits.b.b3 ^ bits.a.b3;
      cur.b2 = (0 - ((bidx >> 11) & 1)) ^ tw1_c[tw_off_a + 2] ^ bits.b.b2 ^ bits.a.b2;
      cur.b1 = (0 - ((bidx >> 10) & 1)) ^ tw1_c[tw_off_a + 1] ^ bits.b.b1 ^ bits.a.b1;
      cur.b0 = (0 - ((bidx >> 9)  & 1)) ^ tw1_c[tw_off_a]     ^ bits.b.b0 ^ bits.a.b0;
      break;
    case 3:
      cur.b7 = (0 - ((tidx >> 2)  & 1)) ^ tw1_c[tw_off_a + 7] ^ bits.b.b7 ^ bits.a.b7;
      cur.b6 = (0 - ((tidx >> 1)  & 1)) ^ tw1_c[tw_off_a + 6] ^ bits.b.b6 ^ bits.a.b6;
      cur.b5 = (0 -  (tidx        & 1)) ^ tw1_c[tw_off_a + 5] ^ bits.b.b5 ^ bits.a.b5;
      cur.b4 = 0xffff0000               ^ tw1_c[tw_off_a + 4] ^ bits.b.b4 ^ bits.a.b4;
      cur.b3 = 0xff00ff00               ^ tw1_c[tw_off_a + 3] ^ bits.b.b3 ^ bits.a.b3;
      cur.b2 = 0xf0f0f0f0               ^ tw1_c[tw_off_a + 2] ^ bits.b.b2 ^ bits.a.b2;
      cur.b1 = 0xcccccccc               ^ tw1_c[tw_off_a + 1] ^ bits.b.b1 ^ bits.a.b1;
      cur.b0 = 0xaaaaaaaa               ^ tw1_c[tw_off_a]     ^ bits.b.b0 ^ bits.a.b0;
      break;
    case 4:
      cur.b7 = key_hi[7]                ^ tw1_c[tw_off_a + 7] ^ bits.b.b7 ^ bits.a.b7;
      cur.b6 = key_hi[6]                ^ tw1_c[tw_off_a + 6] ^ bits.b.b6 ^ bits.a.b6;
      cur.b5 = key_hi[5]                ^ tw1_c[tw_off_a + 5] ^ bits.b.b5 ^ bits.a.b5;
      cur.b4 = key_hi[4]                ^ tw1_c[tw_off_a + 4] ^ bits.b.b4 ^ bits.a.b4;
      cur.b3 = key_hi[3]                ^ tw1_c[tw_off_a + 3] ^ bits.b.b3 ^ bits.a.b3;
      cur.b2 = key_hi[2]                ^ tw1_c[tw_off_a + 2] ^ bits.b.b2 ^ bits.a.b2;
      cur.b1 = key_hi[1]                ^ tw1_c[tw_off_a + 1] ^ bits.b.b1 ^ bits.a.b1;
      cur.b0 = key_hi[0]                ^ tw1_c[tw_off_a]     ^ bits.b.b0 ^ bits.a.b0;
      break;
    case 5:
      cur.b7 = (0 -  (bidx        & 1)) ^ tw1_c[tw_off_a + 7] ^ bits.b.b7 ^ bits.a.b7;
      cur.b6 = (0 - ((tidx >> 9)  & 1)) ^ tw1_c[tw_off_a + 6] ^ bits.b.b6 ^ bits.a.b6;
      cur.b5 = (0 - ((tidx >> 8)  & 1)) ^ tw1_c[tw_off_a + 5] ^ bits.b.b5 ^ bits.a.b5;
      cur.b4 = (0 - ((tidx >> 7)  & 1)) ^ tw1_c[tw_off_a + 4] ^ bits.b.b4 ^ bits.a.b4;
      cur.b3 = (0 - ((tidx >> 6)  & 1)) ^ tw1_c[tw_off_a + 3] ^ bits.b.b3 ^ bits.a.b3;
      cur.b2 = (0 - ((tidx >> 5)  & 1)) ^ tw1_c[tw_off_a + 2] ^ bits.b.b2 ^ bits.a.b2;
      cur.b1 = (0 - ((tidx >> 4)  & 1)) ^ tw1_c[tw_off_a + 1] ^ bits.b.b1 ^ bits.a.b1;
      cur.b0 = (0 - ((tidx >> 3)  & 1)) ^ tw1_c[tw_off_a]     ^ bits.b.b0 ^ bits.a.b0;
      break;
    case 6:
      cur.b7 = key_hi[15]               ^ tw1_c[tw_off_a + 7] ^ bits.b.b7 ^ bits.a.b7;
      cur.b6 = key_hi[14]               ^ tw1_c[tw_off_a + 6] ^ bits.b.b6 ^ bits.a.b6;
      cur.b5 = key_hi[13]               ^ tw1_c[tw_off_a + 5] ^ bits.b.b5 ^ bits.a.b5;
      cur.b4 = key_hi[12]               ^ tw1_c[tw_off_a + 4] ^ bits.b.b4 ^ bits.a.b4;
      cur.b3 = key_hi[11]               ^ tw1_c[tw_off_a + 3] ^ bits.b.b3 ^ bits.a.b3;
      cur.b2 = key_hi[10]               ^ tw1_c[tw_off_a + 2] ^ bits.b.b2 ^ bits.a.b2;
      cur.b1 = key_hi[9]                ^ tw1_c[tw_off_a + 1] ^ bits.b.b1 ^ bits.a.b1;
      cur.b0 = key_hi[8]                ^ tw1_c[tw_off_a]     ^ bits.b.b0 ^ bits.a.b0;
      break;
  }

  if (last) {
    bits.a = cur;
  } else {
    bits.a.b0 = s0(cur);
    bits.a.b1 = s1(cur);
    bits.a.b2 = s2(cur);
    bits.a.b3 = s3(cur);
    bits.a.b4 = s4(cur);
    bits.a.b5 = s5(cur);
    bits.a.b6 = s6(cur);
    bits.a.b7 = s7(cur);
  }

  /* C xor B xor key xor tweak. */
  switch (round % 7) {
    case 0:
      cur.b7 = (0 -  (bidx        & 1)) ^ tw1_c[tw_off_c + 7] ^ bits.b.b7 ^ bits.c.b7;
      cur.b6 = (0 - ((tidx >> 9)  & 1)) ^ tw1_c[tw_off_c + 6] ^ bits.b.b6 ^ bits.c.b6;
      cur.b5 = (0 - ((tidx >> 8)  & 1)) ^ tw1_c[tw_off_c + 5] ^ bits.b.b5 ^ bits.c.b5;
      cur.b4 = (0 - ((tidx >> 7)  & 1)) ^ tw1_c[tw_off_c + 4] ^ bits.b.b4 ^ bits.c.b4;
      cur.b3 = (0 - ((tidx >> 6)  & 1)) ^ tw1_c[tw_off_c + 3] ^ bits.b.b3 ^ bits.c.b3;
      cur.b2 = (0 - ((tidx >> 5)  & 1)) ^ tw1_c[tw_off_c + 2] ^ bits.b.b2 ^ bits.c.b2;
      cur.b1 = (0 - ((tidx >> 4)  & 1)) ^ tw1_c[tw_off_c + 1] ^ bits.b.b1 ^ bits.c.b1;
      cur.b0 = (0 - ((tidx >> 3)  & 1)) ^ tw1_c[tw_off_c]     ^ bits.b.b0 ^ bits.c.b0;
      break;
    case 1:
      cur.b7 = key_hi[15]               ^ tw1_c[tw_off_c + 7] ^ bits.b.b7 ^ bits.c.b7;
      cur.b6 = key_hi[14]               ^ tw1_c[tw_off_c + 6] ^ bits.b.b6 ^ bits.c.b6;
      cur.b5 = key_hi[13]               ^ tw1_c[tw_off_c + 5] ^ bits.b.b5 ^ bits.c.b5;
      cur.b4 = key_hi[12]               ^ tw1_c[tw_off_c + 4] ^ bits.b.b4 ^ bits.c.b4;
      cur.b3 = key_hi[11]               ^ tw1_c[tw_off_c + 3] ^ bits.b.b3 ^ bits.c.b3;
      cur.b2 = key_hi[10]               ^ tw1_c[tw_off_c + 2] ^ bits.b.b2 ^ bits.c.b2;
      cur.b1 = key_hi[9]                ^ tw1_c[tw_off_c + 1] ^ bits.b.b1 ^ bits.c.b1;
      cur.b0 = key_hi[8]                ^ tw1_c[tw_off_c]     ^ bits.b.b0 ^ bits.c.b0;
      break;
    case 2:
      cur.b7 = (0 - ((bidx >> 8)  & 1)) ^ tw1_c[tw_off_c + 7] ^ bits.b.b7 ^ bits.c.b7;
      cur.b6 = (0 - ((bidx >> 7)  & 1)) ^ tw1_c[tw_off_c + 6] ^ bits.b.b6 ^ bits.c.b6;
      cur.b5 = (0 - ((bidx >> 6)  & 1)) ^ tw1_c[tw_off_c + 5] ^ bits.b.b5 ^ bits.c.b5;
      cur.b4 = (0 - ((bidx >> 5)  & 1)) ^ tw1_c[tw_off_c + 4] ^ bits.b.b4 ^ bits.c.b4;
      cur.b3 = (0 - ((bidx >> 4)  & 1)) ^ tw1_c[tw_off_c + 3] ^ bits.b.b3 ^ bits.c.b3;
      cur.b2 = (0 - ((bidx >> 3)  & 1)) ^ tw1_c[tw_off_c + 2] ^ bits.b.b2 ^ bits.c.b2;
      cur.b1 = (0 - ((bidx >> 2)  & 1)) ^ tw1_c[tw_off_c + 1] ^ bits.b.b1 ^ bits.c.b1;
      cur.b0 = (0 - ((bidx >> 1)  & 1)) ^ tw1_c[tw_off_c]     ^ bits.b.b0 ^ bits.c.b0;
      break;
    case 3:
      cur.b7 = key_hi[23]               ^ tw1_c[tw_off_c + 7] ^ bits.b.b7 ^ bits.c.b7;
      cur.b6 = key_hi[22]               ^ tw1_c[tw_off_c + 6] ^ bits.b.b6 ^ bits.c.b6;
      cur.b5 = key_hi[21]               ^ tw1_c[tw_off_c + 5] ^ bits.b.b5 ^ bits.c.b5;
      cur.b4 = key_hi[20]               ^ tw1_c[tw_off_c + 4] ^ bits.b.b4 ^ bits.c.b4;
      cur.b3 = key_hi[19]               ^ tw1_c[tw_off_c + 3] ^ bits.b.b3 ^ bits.c.b3;
      cur.b2 = key_hi[18]               ^ tw1_c[tw_off_c + 2] ^ bits.b.b2 ^ bits.c.b2;
      cur.b1 = key_hi[17]               ^ tw1_c[tw_off_c + 1] ^ bits.b.b1 ^ bits.c.b1;
      cur.b0 = key_hi[16]               ^ tw1_c[tw_off_c]     ^ bits.b.b0 ^ bits.c.b0;
      break;
    case 4:
      cur.b7 = (0 - ((bidx >> 16) & 1)) ^ tw1_c[tw_off_c + 7] ^ bits.b.b7 ^ bits.c.b7;
      cur.b6 = (0 - ((bidx >> 15) & 1)) ^ tw1_c[tw_off_c + 6] ^ bits.b.b6 ^ bits.c.b6;
      cur.b5 = (0 - ((bidx >> 14) & 1)) ^ tw1_c[tw_off_c + 5] ^ bits.b.b5 ^ bits.c.b5;
      cur.b4 = (0 - ((bidx >> 13) & 1)) ^ tw1_c[tw_off_c + 4] ^ bits.b.b4 ^ bits.c.b4;
      cur.b3 = (0 - ((bidx >> 12) & 1)) ^ tw1_c[tw_off_c + 3] ^ bits.b.b3 ^ bits.c.b3;
      cur.b2 = (0 - ((bidx >> 11) & 1)) ^ tw1_c[tw_off_c + 2] ^ bits.b.b2 ^ bits.c.b2;
      cur.b1 = (0 - ((bidx >> 10) & 1)) ^ tw1_c[tw_off_c + 1] ^ bits.b.b1 ^ bits.c.b1;
      cur.b0 = (0 - ((bidx >> 9)  & 1)) ^ tw1_c[tw_off_c]     ^ bits.b.b0 ^ bits.c.b0;
      break;
    case 5:
      cur.b7 = (0 - ((tidx >> 2)  & 1)) ^ tw1_c[tw_off_c + 7] ^ bits.b.b7 ^ bits.c.b7;
      cur.b6 = (0 - ((tidx >> 1)  & 1)) ^ tw1_c[tw_off_c + 6] ^ bits.b.b6 ^ bits.c.b6;
      cur.b5 = (0 -  (tidx        & 1)) ^ tw1_c[tw_off_c + 5] ^ bits.b.b5 ^ bits.c.b5;
      cur.b4 = 0xffff0000               ^ tw1_c[tw_off_c + 4] ^ bits.b.b4 ^ bits.c.b4;
      cur.b3 = 0xff00ff00               ^ tw1_c[tw_off_c + 3] ^ bits.b.b3 ^ bits.c.b3;
      cur.b2 = 0xf0f0f0f0               ^ tw1_c[tw_off_c + 2] ^ bits.b.b2 ^ bits.c.b2;
      cur.b1 = 0xcccccccc               ^ tw1_c[tw_off_c + 1] ^ bits.b.b1 ^ bits.c.b1;
      cur.b0 = 0xaaaaaaaa               ^ tw1_c[tw_off_c]     ^ bits.b.b0 ^ bits.c.b0;
      break;
    case 6:
      cur.b7 = key_hi[7]                ^ tw1_c[tw_off_c + 7] ^ bits.b.b7 ^ bits.c.b7;
      cur.b6 = key_hi[6]                ^ tw1_c[tw_off_c + 6] ^ bits.b.b6 ^ bits.c.b6;
      cur.b5 = key_hi[5]                ^ tw1_c[tw_off_c + 5] ^ bits.b.b5 ^ bits.c.b5;
      cur.b4 = key_hi[4]                ^ tw1_c[tw_off_c + 4] ^ bits.b.b4 ^ bits.c.b4;
      cur.b3 = key_hi[3]                ^ tw1_c[tw_off_c + 3] ^ bits.b.b3 ^ bits.c.b3;
      cur.b2 = key_hi[2]                ^ tw1_c[tw_off_c + 2] ^ bits.b.b2 ^ bits.c.b2;
      cur.b1 = key_hi[1]                ^ tw1_c[tw_off_c + 1] ^ bits.b.b1 ^ bits.c.b1;
      cur.b0 = key_hi[0]                ^ tw1_c[tw_off_c]     ^ bits.b.b0 ^ bits.c.b0;
      break;
  }

  if (last) {
    bits.c = cur;
  } else {
    bits.c.b0 = s0(cur);
    bits.c.b1 = s1(cur);
    bits.c.b2 = s2(cur);
    bits.c.b3 = s3(cur);
    bits.c.b4 = s4(cur);
    bits.c.b5 = s5(cur);
    bits.c.b6 = s6(cur);
    bits.c.b7 = s7(cur);
  }

  /* B xor key xor tweak. */
  switch (round % 7) {
    case 0:
      cur.b7 = (0 - ((tidx >> 2) & 1))  ^ tw1_c[tw_off_b + 7] ^ bits.b.b7;
      cur.b6 = (0 - ((tidx >> 1) & 1))  ^ tw1_c[tw_off_b + 6] ^ bits.b.b6;
      cur.b5 = (0 -  (tidx       & 1))  ^ tw1_c[tw_off_b + 5] ^ bits.b.b5;
      cur.b4 = 0xffff0000               ^ tw1_c[tw_off_b + 4] ^ bits.b.b4;
      cur.b3 = 0xff00ff00               ^ tw1_c[tw_off_b + 3] ^ bits.b.b3;
      cur.b2 = 0xf0f0f0f0               ^ tw1_c[tw_off_b + 2] ^ bits.b.b2;
      cur.b1 = 0xcccccccc               ^ tw1_c[tw_off_b + 1] ^ bits.b.b1;
      cur.b0 = 0xaaaaaaaa               ^ tw1_c[tw_off_b]     ^ bits.b.b0;
      break;
    case 1:
      cur.b7 = key_hi[7]                ^ tw1_c[tw_off_b + 7] ^ bits.b.b7;
      cur.b6 = key_hi[6]                ^ tw1_c[tw_off_b + 6] ^ bits.b.b6;
      cur.b5 = key_hi[5]                ^ tw1_c[tw_off_b + 5] ^ bits.b.b5;
      cur.b4 = key_hi[4]                ^ tw1_c[tw_off_b + 4] ^ bits.b.b4;
      cur.b3 = key_hi[3]                ^ tw1_c[tw_off_b + 3] ^ bits.b.b3;
      cur.b2 = key_hi[2]                ^ tw1_c[tw_off_b + 2] ^ bits.b.b2;
      cur.b1 = key_hi[1]                ^ tw1_c[tw_off_b + 1] ^ bits.b.b1;
      cur.b0 = key_hi[0]                ^ tw1_c[tw_off_b]     ^ bits.b.b0;
      break;
    case 2:
      cur.b7 = (0 -  (bidx        & 1)) ^ tw1_c[tw_off_b + 7] ^ bits.b.b7;
      cur.b6 = (0 - ((tidx >> 9)  & 1)) ^ tw1_c[tw_off_b + 6] ^ bits.b.b6;
      cur.b5 = (0 - ((tidx >> 8)  & 1)) ^ tw1_c[tw_off_b + 5] ^ bits.b.b5;
      cur.b4 = (0 - ((tidx >> 7)  & 1)) ^ tw1_c[tw_off_b + 4] ^ bits.b.b4;
      cur.b3 = (0 - ((tidx >> 6)  & 1)) ^ tw1_c[tw_off_b + 3] ^ bits.b.b3;
      cur.b2 = (0 - ((tidx >> 5)  & 1)) ^ tw1_c[tw_off_b + 2] ^ bits.b.b2;
      cur.b1 = (0 - ((tidx >> 4)  & 1)) ^ tw1_c[tw_off_b + 1] ^ bits.b.b1;
      cur.b0 = (0 - ((tidx >> 3)  & 1)) ^ tw1_c[tw_off_b]     ^ bits.b.b0;
      break;
    case 3:
      cur.b7 = key_hi[15]               ^ tw1_c[tw_off_b + 7] ^ bits.b.b7;
      cur.b6 = key_hi[14]               ^ tw1_c[tw_off_b + 6] ^ bits.b.b6;
      cur.b5 = key_hi[13]               ^ tw1_c[tw_off_b + 5] ^ bits.b.b5;
      cur.b4 = key_hi[12]               ^ tw1_c[tw_off_b + 4] ^ bits.b.b4;
      cur.b3 = key_hi[11]               ^ tw1_c[tw_off_b + 3] ^ bits.b.b3;
      cur.b2 = key_hi[10]               ^ tw1_c[tw_off_b + 2] ^ bits.b.b2;
      cur.b1 = key_hi[9]                ^ tw1_c[tw_off_b + 1] ^ bits.b.b1;
      cur.b0 = key_hi[8]                ^ tw1_c[tw_off_b]     ^ bits.b.b0;
      break;
    case 4:
      cur.b7 = (0 - ((bidx >> 8)  & 1)) ^ tw1_c[tw_off_b + 7] ^ bits.b.b7;
      cur.b6 = (0 - ((bidx >> 7)  & 1)) ^ tw1_c[tw_off_b + 6] ^ bits.b.b6;
      cur.b5 = (0 - ((bidx >> 6)  & 1)) ^ tw1_c[tw_off_b + 5] ^ bits.b.b5;
      cur.b4 = (0 - ((bidx >> 5)  & 1)) ^ tw1_c[tw_off_b + 4] ^ bits.b.b4;
      cur.b3 = (0 - ((bidx >> 4)  & 1)) ^ tw1_c[tw_off_b + 3] ^ bits.b.b3;
      cur.b2 = (0 - ((bidx >> 3)  & 1)) ^ tw1_c[tw_off_b + 2] ^ bits.b.b2;
      cur.b1 = (0 - ((bidx >> 2)  & 1)) ^ tw1_c[tw_off_b + 1] ^ bits.b.b1;
      cur.b0 = (0 - ((bidx >> 1)  & 1)) ^ tw1_c[tw_off_b]     ^ bits.b.b0;
      break;
    case 5:
      cur.b7 = key_hi[23]               ^ tw1_c[tw_off_b + 7] ^ bits.b.b7;
      cur.b6 = key_hi[22]               ^ tw1_c[tw_off_b + 6] ^ bits.b.b6;
      cur.b5 = key_hi[21]               ^ tw1_c[tw_off_b + 5] ^ bits.b.b5;
      cur.b4 = key_hi[20]               ^ tw1_c[tw_off_b + 4] ^ bits.b.b4;
      cur.b3 = key_hi[19]               ^ tw1_c[tw_off_b + 3] ^ bits.b.b3;
      cur.b2 = key_hi[18]               ^ tw1_c[tw_off_b + 2] ^ bits.b.b2;
      cur.b1 = key_hi[17]               ^ tw1_c[tw_off_b + 1] ^ bits.b.b1;
      cur.b0 = key_hi[16]               ^ tw1_c[tw_off_b]     ^ bits.b.b0;
      break;
    case 6:
      cur.b7 = (0 - ((bidx >> 16) & 1)) ^ tw1_c[tw_off_b + 7] ^ bits.b.b7;
      cur.b6 = (0 - ((bidx >> 15) & 1)) ^ tw1_c[tw_off_b + 6] ^ bits.b.b6;
      cur.b5 = (0 - ((bidx >> 14) & 1)) ^ tw1_c[tw_off_b + 5] ^ bits.b.b5;
      cur.b4 = (0 - ((bidx >> 13) & 1)) ^ tw1_c[tw_off_b + 4] ^ bits.b.b4;
      cur.b3 = (0 - ((bidx >> 12) & 1)) ^ tw1_c[tw_off_b + 3] ^ bits.b.b3;
      cur.b2 = (0 - ((bidx >> 11) & 1)) ^ tw1_c[tw_off_b + 2] ^ bits.b.b2;
      cur.b1 = (0 - ((bidx >> 10) & 1)) ^ tw1_c[tw_off_b + 1] ^ bits.b.b1;
      cur.b0 = (0 - ((bidx >> 9)  & 1)) ^ tw1_c[tw_off_b]     ^ bits.b.b0;
      break;
  }

  if (last) {
    bits.b = cur;
  } else {
    cur.b0 ^= bits.a.b0 ^ bits.c.b0;
    cur.b1 ^= bits.a.b1 ^ bits.c.b1;
    cur.b2 ^= bits.a.b2 ^ bits.c.b2;
    cur.b3 ^= bits.a.b3 ^ bits.c.b3;
    cur.b4 ^= bits.a.b4 ^ bits.c.b4;
    cur.b5 ^= bits.a.b5 ^ bits.c.b5;
    cur.b6 ^= bits.a.b6 ^ bits.c.b6;
    cur.b7 ^= bits.a.b7 ^ bits.c.b7;
    bits.b.b0 = s0(cur);
    bits.b.b1 = s1(cur);
    bits.b.b2 = s2(cur);
    bits.b.b3 = s3(cur);
    bits.b.b4 = s4(cur);
    bits.b.b5 = s5(cur);
    bits.b.b6 = s6(cur);
    bits.b.b7 = s7(cur);
  }

  return bits;
}

/* Brute force search for key. The five least significant bytes of matching
   keys are placed in ret. */
template<int rounds>
__launch_bounds__(1024, 1)
__global__ void brute_force(int *ret, volatile int off) {
  __shared__ int pt[24];
  __shared__ int ct[24];
  __shared__ int key_12[24];
  __shared__ int found[100];
  if (threadIdx.x < 24) {
    pt[threadIdx.x] = pt1_c[threadIdx.x + off];
    ct[threadIdx.x] = ct1_c[threadIdx.x + off];
    key_12[threadIdx.x] = key_c[threadIdx.x + off];
    found[threadIdx.x] = 0;
  }

  __syncthreads();

  twentyfourbits bits;
  bits.a.b7 = pt[23];
  bits.a.b6 = pt[22];
  bits.a.b5 = pt[21];
  bits.a.b4 = pt[20];
  bits.a.b3 = pt[19];
  bits.a.b2 = pt[18];
  bits.a.b1 = pt[17];
  bits.a.b0 = pt[16];
  bits.b.b7 = pt[15];
  bits.b.b6 = pt[14];
  bits.b.b5 = pt[13];
  bits.b.b4 = pt[12];
  bits.b.b3 = pt[11];
  bits.b.b2 = pt[10];
  bits.b.b1 = pt[9];
  bits.b.b0 = pt[8];
  bits.c.b7 = pt[7];
  bits.c.b6 = pt[6];
  bits.c.b5 = pt[5];
  bits.c.b4 = pt[4];
  bits.c.b3 = pt[3];
  bits.c.b2 = pt[2];
  bits.c.b1 = pt[1];
  bits.c.b0 = pt[0];

  #pragma unroll
  for (int i = 2; i < rounds; i++) {
    bits = encrypt_round<false>(bits, i, &key_12[0]);
  }
  bits = encrypt_round<true>(bits, rounds, &key_12[0]);

  int rr = 0;
  rr |= bits.a.b7 ^ ct[23];
  rr |= bits.a.b6 ^ ct[22];
  rr |= bits.a.b5 ^ ct[21];
  rr |= bits.a.b4 ^ ct[20];
  rr |= bits.a.b3 ^ ct[19];
  rr |= bits.a.b2 ^ ct[18];
  rr |= bits.a.b1 ^ ct[17];
  rr |= bits.a.b0 ^ ct[16];
  rr |= bits.b.b7 ^ ct[15];
  rr |= bits.b.b6 ^ ct[14];
  rr |= bits.b.b5 ^ ct[13];
  rr |= bits.b.b4 ^ ct[12];
  rr |= bits.b.b3 ^ ct[11];
  rr |= bits.b.b2 ^ ct[10];
  rr |= bits.b.b1 ^ ct[9];
  rr |= bits.b.b0 ^ ct[8];
  rr |= bits.c.b7 ^ ct[7];
  rr |= bits.c.b6 ^ ct[6];
  rr |= bits.c.b5 ^ ct[5];
  rr |= bits.c.b4 ^ ct[4];
  rr |= bits.c.b3 ^ ct[3];
  rr |= bits.c.b2 ^ ct[2];
  rr |= bits.c.b1 ^ ct[1];
  rr |= bits.c.b0 ^ ct[0];

  /* Put matches in shared memory. */
  int ptr;
  if (rr != 0xffffffff) {
    ptr = atomicAdd_block(found, 1);
    found[ptr + 2] = (blockIdx.x << 10) | threadIdx.x;
    found[ptr + 3] = rr;
  }

  __syncthreads();

  if (found[0] == 0) {
    return;
  }

  /* Get global memory offset for matches found in block. */
  if (threadIdx.x == 0) {
    found[1] = atomicAdd(ret, found[0]) * 2 + 1;
  }

  __syncthreads();

  /* Copy matches to global memory. */
  if (threadIdx.x < found[0]) {
    ptr = found[1] + threadIdx.x * 2;
    ret[ptr]     = found[(threadIdx.x * 2) + 2];
    ret[ptr + 1] = found[(threadIdx.x * 2) + 3];
  }
}

__device__ __forceinline__ eightbits sbox(eightbits in) {
  eightbits out;
  out.b0 = s0(in);
  out.b1 = s1(in);
  out.b2 = s2(in);
  out.b3 = s3(in);
  out.b4 = s4(in);
  out.b5 = s5(in);
  out.b6 = s6(in);
  out.b7 = s7(in);
  return out;
}

/* Tests candidates found by find_candidates. Used when cracking 6, 7, and 8
   rounds. The five least significant bytes of matching keys are placed in ret. */
template <int rounds>
__launch_bounds__(1024, 1)
__global__ void test_candidates(int *in, int *out, int num_candidates, int offset) {

  int ptr = ((blockIdx.x << 7) | (threadIdx.x >> 3));
  if (ptr >= num_candidates) {
    return;
  }

  volatile __shared__ int pt1[24];
  volatile __shared__ int ct1[24];
  volatile __shared__ int tw1[64];
  volatile __shared__ int key_12[16];
  volatile __shared__ int k3456[1024];
  __shared__ int found[1024];
  __shared__ eightbits aa[1024];

  if (threadIdx.x < 16) {
    key_12[threadIdx.x] = key_c[threadIdx.x + offset * 16];
  }
  if (threadIdx.x < 24) {
    pt1[threadIdx.x] = pt1_c[threadIdx.x + offset * 24];
    ct1[threadIdx.x] = ct1_c[threadIdx.x + offset * 24];
  }
  if (threadIdx.x < 64) {
    tw1[threadIdx.x] = tw1_c[threadIdx.x + offset * 64];
  }

  __syncthreads();

  k3456[threadIdx.x] = in[ptr + 1];

  eightbits bb, cc;

  /* Round 1. */
  bb.b0 = pt1[8];
  bb.b1 = pt1[9];
  bb.b2 = pt1[10];
  bb.b3 = pt1[11];
  bb.b4 = pt1[12];
  bb.b5 = pt1[13];
  bb.b6 = pt1[14];
  bb.b7 = pt1[15];
  aa[threadIdx.x].b0 = pt1[16] ^ bb.b0 ^ key_12[8]  ^ tw1[56];
  aa[threadIdx.x].b1 = pt1[17] ^ bb.b1 ^ key_12[9]  ^ tw1[57];
  aa[threadIdx.x].b2 = pt1[18] ^ bb.b2 ^ key_12[10] ^ tw1[58];
  aa[threadIdx.x].b3 = pt1[19] ^ bb.b3 ^ key_12[11] ^ tw1[59];
  aa[threadIdx.x].b4 = pt1[20] ^ bb.b4 ^ key_12[12] ^ tw1[60];
  aa[threadIdx.x].b5 = pt1[21] ^ bb.b5 ^ key_12[13] ^ tw1[61];
  aa[threadIdx.x].b6 = pt1[22] ^ bb.b6 ^ key_12[14] ^ tw1[62];
  aa[threadIdx.x].b7 = pt1[23] ^ bb.b7 ^ key_12[15] ^ tw1[63];
  aa[threadIdx.x] = sbox(aa[threadIdx.x]);

  cc.b0 = pt1[0]  ^ bb.b0 ^ key_12[0] ^ tw1[48];
  cc.b1 = pt1[1]  ^ bb.b1 ^ key_12[1] ^ tw1[49];
  cc.b2 = pt1[2]  ^ bb.b2 ^ key_12[2] ^ tw1[50];
  cc.b3 = pt1[3]  ^ bb.b3 ^ key_12[3] ^ tw1[51];
  cc.b4 = pt1[4]  ^ bb.b4 ^ key_12[4] ^ tw1[52];
  cc.b5 = pt1[5]  ^ bb.b5 ^ key_12[5] ^ tw1[53];
  cc.b6 = pt1[6]  ^ bb.b6 ^ key_12[6] ^ tw1[54];
  cc.b7 = pt1[7]  ^ bb.b7 ^ key_12[7] ^ tw1[55];
  cc = sbox(cc);

  bb.b0 ^= aa[threadIdx.x].b0  ^ cc.b0 ^ (0 - ((k3456[threadIdx.x] >> 24) & 1)) ^ tw1[40];
  bb.b1 ^= aa[threadIdx.x].b1  ^ cc.b1 ^ (0 - ((k3456[threadIdx.x] >> 25) & 1)) ^ tw1[41];
  bb.b2 ^= aa[threadIdx.x].b2  ^ cc.b2 ^ (0 - ((k3456[threadIdx.x] >> 26) & 1)) ^ tw1[42];
  bb.b3 ^= aa[threadIdx.x].b3  ^ cc.b3 ^ (0 - ((k3456[threadIdx.x] >> 27) & 1)) ^ tw1[43];
  bb.b4 ^= aa[threadIdx.x].b4  ^ cc.b4 ^ (0 - ((k3456[threadIdx.x] >> 28) & 1)) ^ tw1[44];
  bb.b5 ^= aa[threadIdx.x].b5  ^ cc.b5 ^ (0 - ((k3456[threadIdx.x] >> 29) & 1)) ^ tw1[45];
  bb.b6 ^= aa[threadIdx.x].b6  ^ cc.b6 ^ (0 - ((k3456[threadIdx.x] >> 30) & 1)) ^ tw1[46];
  bb.b7 ^= aa[threadIdx.x].b7  ^ cc.b7 ^ (0 - ((k3456[threadIdx.x] >> 31) & 1)) ^ tw1[47];
  bb = sbox(bb);

  /* Round 2. */
  aa[threadIdx.x].b0 ^= bb.b0 ^ (0 - ((k3456[threadIdx.x] >> 16) & 1)) ^ tw1[32];
  aa[threadIdx.x].b1 ^= bb.b1 ^ (0 - ((k3456[threadIdx.x] >> 17) & 1)) ^ tw1[33];
  aa[threadIdx.x].b2 ^= bb.b2 ^ (0 - ((k3456[threadIdx.x] >> 18) & 1)) ^ tw1[34];
  aa[threadIdx.x].b3 ^= bb.b3 ^ (0 - ((k3456[threadIdx.x] >> 19) & 1)) ^ tw1[35];
  aa[threadIdx.x].b4 ^= bb.b4 ^ (0 - ((k3456[threadIdx.x] >> 20) & 1)) ^ tw1[36];
  aa[threadIdx.x].b5 ^= bb.b5 ^ (0 - ((k3456[threadIdx.x] >> 21) & 1)) ^ tw1[37];
  aa[threadIdx.x].b6 ^= bb.b6 ^ (0 - ((k3456[threadIdx.x] >> 22) & 1)) ^ tw1[38];
  aa[threadIdx.x].b7 ^= bb.b7 ^ (0 - ((k3456[threadIdx.x] >> 23) & 1)) ^ tw1[39];
  aa[threadIdx.x] = sbox(aa[threadIdx.x]);

  cc.b0 ^= bb.b0 ^ (0 - ((k3456[threadIdx.x] >> 8)  & 1)) ^ tw1[24];
  cc.b1 ^= bb.b1 ^ (0 - ((k3456[threadIdx.x] >> 9)  & 1)) ^ tw1[25];
  cc.b2 ^= bb.b2 ^ (0 - ((k3456[threadIdx.x] >> 10) & 1)) ^ tw1[26];
  cc.b3 ^= bb.b3 ^ (0 - ((k3456[threadIdx.x] >> 11) & 1)) ^ tw1[27];
  cc.b4 ^= bb.b4 ^ (0 - ((k3456[threadIdx.x] >> 12) & 1)) ^ tw1[28];
  cc.b5 ^= bb.b5 ^ (0 - ((k3456[threadIdx.x] >> 13) & 1)) ^ tw1[29];
  cc.b6 ^= bb.b6 ^ (0 - ((k3456[threadIdx.x] >> 14) & 1)) ^ tw1[30];
  cc.b7 ^= bb.b7 ^ (0 - ((k3456[threadIdx.x] >> 15) & 1)) ^ tw1[31];
  cc = sbox(cc);

  bb.b0 ^= aa[threadIdx.x].b0 ^ cc.b0 ^ (0 - ((k3456[threadIdx.x] >> 0) & 1)) ^ tw1[16];
  bb.b1 ^= aa[threadIdx.x].b1 ^ cc.b1 ^ (0 - ((k3456[threadIdx.x] >> 1) & 1)) ^ tw1[17];
  bb.b2 ^= aa[threadIdx.x].b2 ^ cc.b2 ^ (0 - ((k3456[threadIdx.x] >> 2) & 1)) ^ tw1[18];
  bb.b3 ^= aa[threadIdx.x].b3 ^ cc.b3 ^ (0 - ((k3456[threadIdx.x] >> 3) & 1)) ^ tw1[19];
  bb.b4 ^= aa[threadIdx.x].b4 ^ cc.b4 ^ (0 - ((k3456[threadIdx.x] >> 4) & 1)) ^ tw1[20];
  bb.b5 ^= aa[threadIdx.x].b5 ^ cc.b5 ^ (0 - ((k3456[threadIdx.x] >> 5) & 1)) ^ tw1[21];
  bb.b6 ^= aa[threadIdx.x].b6 ^ cc.b6 ^ (0 - ((k3456[threadIdx.x] >> 6) & 1)) ^ tw1[22];
  bb.b7 ^= aa[threadIdx.x].b7 ^ cc.b7 ^ (0 - ((k3456[threadIdx.x] >> 7) & 1)) ^ tw1[23];
  bb = sbox(bb);

  /* Round 3. */
  aa[threadIdx.x].b0 ^= bb.b0 ^ 0xaaaaaaaa                     ^ tw1[8];
  aa[threadIdx.x].b1 ^= bb.b1 ^ 0xcccccccc                     ^ tw1[9];
  aa[threadIdx.x].b2 ^= bb.b2 ^ 0xf0f0f0f0                     ^ tw1[10];
  aa[threadIdx.x].b3 ^= bb.b3 ^ 0xff00ff00                     ^ tw1[11];
  aa[threadIdx.x].b4 ^= bb.b4 ^ 0xffff0000                     ^ tw1[12];
  aa[threadIdx.x].b5 ^= bb.b5 ^ (0 -  (threadIdx.x       & 1)) ^ tw1[13];
  aa[threadIdx.x].b6 ^= bb.b6 ^ (0 - ((threadIdx.x >> 1) & 1)) ^ tw1[14];
  aa[threadIdx.x].b7 ^= bb.b7 ^ (0 - ((threadIdx.x >> 2) & 1)) ^ tw1[15];
  aa[threadIdx.x] = sbox(aa[threadIdx.x]);

  cc.b0 ^= bb.b0 ^ key_12[8] ^  tw1[0];
  cc.b1 ^= bb.b1 ^ key_12[9] ^  tw1[1];
  cc.b2 ^= bb.b2 ^ key_12[10] ^ tw1[2];
  cc.b3 ^= bb.b3 ^ key_12[11] ^ tw1[3];
  cc.b4 ^= bb.b4 ^ key_12[12] ^ tw1[4];
  cc.b5 ^= bb.b5 ^ key_12[13] ^ tw1[5];
  cc.b6 ^= bb.b6 ^ key_12[14] ^ tw1[6];
  cc.b7 ^= bb.b7 ^ key_12[15] ^ tw1[7];
  cc = sbox(cc);

  bb.b0 ^= aa[threadIdx.x].b0 ^ cc.b0 ^ key_12[0] ^ tw1[56];
  bb.b1 ^= aa[threadIdx.x].b1 ^ cc.b1 ^ key_12[1] ^ tw1[57];
  bb.b2 ^= aa[threadIdx.x].b2 ^ cc.b2 ^ key_12[2] ^ tw1[58];
  bb.b3 ^= aa[threadIdx.x].b3 ^ cc.b3 ^ key_12[3] ^ tw1[59];
  bb.b4 ^= aa[threadIdx.x].b4 ^ cc.b4 ^ key_12[4] ^ tw1[60];
  bb.b5 ^= aa[threadIdx.x].b5 ^ cc.b5 ^ key_12[5] ^ tw1[61];
  bb.b6 ^= aa[threadIdx.x].b6 ^ cc.b6 ^ key_12[6] ^ tw1[62];
  bb.b7 ^= aa[threadIdx.x].b7 ^ cc.b7 ^ key_12[7] ^ tw1[63];
  bb = sbox(bb);

  /* Round 4. */
  aa[threadIdx.x].b0 ^= bb.b0 ^ (0 - ((k3456[threadIdx.x] >> 24) & 1)) ^ tw1[48];
  aa[threadIdx.x].b1 ^= bb.b1 ^ (0 - ((k3456[threadIdx.x] >> 25) & 1)) ^ tw1[49];
  aa[threadIdx.x].b2 ^= bb.b2 ^ (0 - ((k3456[threadIdx.x] >> 26) & 1)) ^ tw1[50];
  aa[threadIdx.x].b3 ^= bb.b3 ^ (0 - ((k3456[threadIdx.x] >> 27) & 1)) ^ tw1[51];
  aa[threadIdx.x].b4 ^= bb.b4 ^ (0 - ((k3456[threadIdx.x] >> 28) & 1)) ^ tw1[52];
  aa[threadIdx.x].b5 ^= bb.b5 ^ (0 - ((k3456[threadIdx.x] >> 29) & 1)) ^ tw1[53];
  aa[threadIdx.x].b6 ^= bb.b6 ^ (0 - ((k3456[threadIdx.x] >> 30) & 1)) ^ tw1[54];
  aa[threadIdx.x].b7 ^= bb.b7 ^ (0 - ((k3456[threadIdx.x] >> 31) & 1)) ^ tw1[55];
  aa[threadIdx.x] = sbox(aa[threadIdx.x]);

  cc.b0 ^= bb.b0 ^ (0 - ((k3456[threadIdx.x] >> 16) & 1)) ^ tw1[40];
  cc.b1 ^= bb.b1 ^ (0 - ((k3456[threadIdx.x] >> 17) & 1)) ^ tw1[41];
  cc.b2 ^= bb.b2 ^ (0 - ((k3456[threadIdx.x] >> 18) & 1)) ^ tw1[42];
  cc.b3 ^= bb.b3 ^ (0 - ((k3456[threadIdx.x] >> 19) & 1)) ^ tw1[43];
  cc.b4 ^= bb.b4 ^ (0 - ((k3456[threadIdx.x] >> 20) & 1)) ^ tw1[44];
  cc.b5 ^= bb.b5 ^ (0 - ((k3456[threadIdx.x] >> 21) & 1)) ^ tw1[45];
  cc.b6 ^= bb.b6 ^ (0 - ((k3456[threadIdx.x] >> 22) & 1)) ^ tw1[46];
  cc.b7 ^= bb.b7 ^ (0 - ((k3456[threadIdx.x] >> 23) & 1)) ^ tw1[47];
  cc = sbox(cc);

  bb.b0 ^= aa[threadIdx.x].b0 ^ cc.b0 ^ (0 - ((k3456[threadIdx.x] >> 8)  & 1)) ^ tw1[32];
  bb.b1 ^= aa[threadIdx.x].b1 ^ cc.b1 ^ (0 - ((k3456[threadIdx.x] >> 9)  & 1)) ^ tw1[33];
  bb.b2 ^= aa[threadIdx.x].b2 ^ cc.b2 ^ (0 - ((k3456[threadIdx.x] >> 10) & 1)) ^ tw1[34];
  bb.b3 ^= aa[threadIdx.x].b3 ^ cc.b3 ^ (0 - ((k3456[threadIdx.x] >> 11) & 1)) ^ tw1[35];
  bb.b4 ^= aa[threadIdx.x].b4 ^ cc.b4 ^ (0 - ((k3456[threadIdx.x] >> 12) & 1)) ^ tw1[36];
  bb.b5 ^= aa[threadIdx.x].b5 ^ cc.b5 ^ (0 - ((k3456[threadIdx.x] >> 13) & 1)) ^ tw1[37];
  bb.b6 ^= aa[threadIdx.x].b6 ^ cc.b6 ^ (0 - ((k3456[threadIdx.x] >> 14) & 1)) ^ tw1[38];
  bb.b7 ^= aa[threadIdx.x].b7 ^ cc.b7 ^ (0 - ((k3456[threadIdx.x] >> 15) & 1)) ^ tw1[39];
  bb = sbox(bb);

  /* Round 5. */
  aa[threadIdx.x].b0 ^= bb.b0 ^ (0 - ((k3456[threadIdx.x] >> 0) & 1)) ^ tw1[24];
  aa[threadIdx.x].b1 ^= bb.b1 ^ (0 - ((k3456[threadIdx.x] >> 1) & 1)) ^ tw1[25];
  aa[threadIdx.x].b2 ^= bb.b2 ^ (0 - ((k3456[threadIdx.x] >> 2) & 1)) ^ tw1[26];
  aa[threadIdx.x].b3 ^= bb.b3 ^ (0 - ((k3456[threadIdx.x] >> 3) & 1)) ^ tw1[27];
  aa[threadIdx.x].b4 ^= bb.b4 ^ (0 - ((k3456[threadIdx.x] >> 4) & 1)) ^ tw1[28];
  aa[threadIdx.x].b5 ^= bb.b5 ^ (0 - ((k3456[threadIdx.x] >> 5) & 1)) ^ tw1[29];
  aa[threadIdx.x].b6 ^= bb.b6 ^ (0 - ((k3456[threadIdx.x] >> 6) & 1)) ^ tw1[30];
  aa[threadIdx.x].b7 ^= bb.b7 ^ (0 - ((k3456[threadIdx.x] >> 7) & 1)) ^ tw1[31];
  aa[threadIdx.x] = sbox(aa[threadIdx.x]);

  cc.b0 ^= bb.b0 ^ 0xaaaaaaaa                     ^ tw1[16];
  cc.b1 ^= bb.b1 ^ 0xcccccccc                     ^ tw1[17];
  cc.b2 ^= bb.b2 ^ 0xf0f0f0f0                     ^ tw1[18];
  cc.b3 ^= bb.b3 ^ 0xff00ff00                     ^ tw1[19];
  cc.b4 ^= bb.b4 ^ 0xffff0000                     ^ tw1[20];
  cc.b5 ^= bb.b5 ^ (0 -  (threadIdx.x       & 1)) ^ tw1[21];
  cc.b6 ^= bb.b6 ^ (0 - ((threadIdx.x >> 1) & 1)) ^ tw1[22];
  cc.b7 ^= bb.b7 ^ (0 - ((threadIdx.x >> 2) & 1)) ^ tw1[23];
  cc = sbox(cc);

  bb.b0 ^= aa[threadIdx.x].b0 ^ cc.b0 ^ key_12[8]  ^ tw1[8];
  bb.b1 ^= aa[threadIdx.x].b1 ^ cc.b1 ^ key_12[9]  ^ tw1[9];
  bb.b2 ^= aa[threadIdx.x].b2 ^ cc.b2 ^ key_12[10] ^ tw1[10];
  bb.b3 ^= aa[threadIdx.x].b3 ^ cc.b3 ^ key_12[11] ^ tw1[11];
  bb.b4 ^= aa[threadIdx.x].b4 ^ cc.b4 ^ key_12[12] ^ tw1[12];
  bb.b5 ^= aa[threadIdx.x].b5 ^ cc.b5 ^ key_12[13] ^ tw1[13];
  bb.b6 ^= aa[threadIdx.x].b6 ^ cc.b6 ^ key_12[14] ^ tw1[14];
  bb.b7 ^= aa[threadIdx.x].b7 ^ cc.b7 ^ key_12[15] ^ tw1[15];
  bb = sbox(bb);

  /* Round 6. */
  aa[threadIdx.x].b0 ^= bb.b0 ^ key_12[0] ^ tw1[0];
  aa[threadIdx.x].b1 ^= bb.b1 ^ key_12[1] ^ tw1[1];
  aa[threadIdx.x].b2 ^= bb.b2 ^ key_12[2] ^ tw1[2];
  aa[threadIdx.x].b3 ^= bb.b3 ^ key_12[3] ^ tw1[3];
  aa[threadIdx.x].b4 ^= bb.b4 ^ key_12[4] ^ tw1[4];
  aa[threadIdx.x].b5 ^= bb.b5 ^ key_12[5] ^ tw1[5];
  aa[threadIdx.x].b6 ^= bb.b6 ^ key_12[6] ^ tw1[6];
  aa[threadIdx.x].b7 ^= bb.b7 ^ key_12[7] ^ tw1[7];
  aa[threadIdx.x] = sbox(aa[threadIdx.x]);

  cc.b0 ^= bb.b0 ^ (0 - ((k3456[threadIdx.x] >> 24) & 1)) ^ tw1[56];
  cc.b1 ^= bb.b1 ^ (0 - ((k3456[threadIdx.x] >> 25) & 1)) ^ tw1[57];
  cc.b2 ^= bb.b2 ^ (0 - ((k3456[threadIdx.x] >> 26) & 1)) ^ tw1[58];
  cc.b3 ^= bb.b3 ^ (0 - ((k3456[threadIdx.x] >> 27) & 1)) ^ tw1[59];
  cc.b4 ^= bb.b4 ^ (0 - ((k3456[threadIdx.x] >> 28) & 1)) ^ tw1[60];
  cc.b5 ^= bb.b5 ^ (0 - ((k3456[threadIdx.x] >> 29) & 1)) ^ tw1[61];
  cc.b6 ^= bb.b6 ^ (0 - ((k3456[threadIdx.x] >> 30) & 1)) ^ tw1[62];
  cc.b7 ^= bb.b7 ^ (0 - ((k3456[threadIdx.x] >> 31) & 1)) ^ tw1[63];
  cc = sbox(cc);

  bb.b0 ^= aa[threadIdx.x].b0 ^ cc.b0 ^ (0 - ((k3456[threadIdx.x] >> 16) & 1)) ^ tw1[48];
  bb.b1 ^= aa[threadIdx.x].b1 ^ cc.b1 ^ (0 - ((k3456[threadIdx.x] >> 17) & 1)) ^ tw1[49];
  bb.b2 ^= aa[threadIdx.x].b2 ^ cc.b2 ^ (0 - ((k3456[threadIdx.x] >> 18) & 1)) ^ tw1[50];
  bb.b3 ^= aa[threadIdx.x].b3 ^ cc.b3 ^ (0 - ((k3456[threadIdx.x] >> 19) & 1)) ^ tw1[51];
  bb.b4 ^= aa[threadIdx.x].b4 ^ cc.b4 ^ (0 - ((k3456[threadIdx.x] >> 20) & 1)) ^ tw1[52];
  bb.b5 ^= aa[threadIdx.x].b5 ^ cc.b5 ^ (0 - ((k3456[threadIdx.x] >> 21) & 1)) ^ tw1[53];
  bb.b6 ^= aa[threadIdx.x].b6 ^ cc.b6 ^ (0 - ((k3456[threadIdx.x] >> 22) & 1)) ^ tw1[54];
  bb.b7 ^= aa[threadIdx.x].b7 ^ cc.b7 ^ (0 - ((k3456[threadIdx.x] >> 23) & 1)) ^ tw1[55];
  bb = sbox(bb);

  /* Round 7. */
  if (rounds > 6) {
    aa[threadIdx.x].b0 ^= bb.b0 ^ (0 - ((k3456[threadIdx.x] >> 8) & 1))  ^ tw1[40];
    aa[threadIdx.x].b1 ^= bb.b1 ^ (0 - ((k3456[threadIdx.x] >> 9) & 1))  ^ tw1[41];
    aa[threadIdx.x].b2 ^= bb.b2 ^ (0 - ((k3456[threadIdx.x] >> 10) & 1)) ^ tw1[42];
    aa[threadIdx.x].b3 ^= bb.b3 ^ (0 - ((k3456[threadIdx.x] >> 11) & 1)) ^ tw1[43];
    aa[threadIdx.x].b4 ^= bb.b4 ^ (0 - ((k3456[threadIdx.x] >> 12) & 1)) ^ tw1[44];
    aa[threadIdx.x].b5 ^= bb.b5 ^ (0 - ((k3456[threadIdx.x] >> 13) & 1)) ^ tw1[45];
    aa[threadIdx.x].b6 ^= bb.b6 ^ (0 - ((k3456[threadIdx.x] >> 14) & 1)) ^ tw1[46];
    aa[threadIdx.x].b7 ^= bb.b7 ^ (0 - ((k3456[threadIdx.x] >> 15) & 1)) ^ tw1[47];
    aa[threadIdx.x] = sbox(aa[threadIdx.x]);

    cc.b0 ^= bb.b0 ^ (0 - ((k3456[threadIdx.x] >> 0) & 1)) ^ tw1[32];
    cc.b1 ^= bb.b1 ^ (0 - ((k3456[threadIdx.x] >> 1) & 1)) ^ tw1[33];
    cc.b2 ^= bb.b2 ^ (0 - ((k3456[threadIdx.x] >> 2) & 1)) ^ tw1[34];
    cc.b3 ^= bb.b3 ^ (0 - ((k3456[threadIdx.x] >> 3) & 1)) ^ tw1[35];
    cc.b4 ^= bb.b4 ^ (0 - ((k3456[threadIdx.x] >> 4) & 1)) ^ tw1[36];
    cc.b5 ^= bb.b5 ^ (0 - ((k3456[threadIdx.x] >> 5) & 1)) ^ tw1[37];
    cc.b6 ^= bb.b6 ^ (0 - ((k3456[threadIdx.x] >> 6) & 1)) ^ tw1[38];
    cc.b7 ^= bb.b7 ^ (0 - ((k3456[threadIdx.x] >> 7) & 1)) ^ tw1[39];
    cc = sbox(cc);

    bb.b0 ^= aa[threadIdx.x].b0 ^ cc.b0 ^ 0xaaaaaaaa                     ^ tw1[24];
    bb.b1 ^= aa[threadIdx.x].b1 ^ cc.b1 ^ 0xcccccccc                     ^ tw1[25];
    bb.b2 ^= aa[threadIdx.x].b2 ^ cc.b2 ^ 0xf0f0f0f0                     ^ tw1[26];
    bb.b3 ^= aa[threadIdx.x].b3 ^ cc.b3 ^ 0xff00ff00                     ^ tw1[27];
    bb.b4 ^= aa[threadIdx.x].b4 ^ cc.b4 ^ 0xffff0000                     ^ tw1[28];
    bb.b5 ^= aa[threadIdx.x].b5 ^ cc.b5 ^ (0 -  (threadIdx.x       & 1)) ^ tw1[29];
    bb.b6 ^= aa[threadIdx.x].b6 ^ cc.b6 ^ (0 - ((threadIdx.x >> 1) & 1)) ^ tw1[30];
    bb.b7 ^= aa[threadIdx.x].b7 ^ cc.b7 ^ (0 - ((threadIdx.x >> 2) & 1)) ^ tw1[31];
    bb = sbox(bb);
  }

  /* Round 8. */
  if (rounds > 7) {
    aa[threadIdx.x].b0 ^= bb.b0 ^ key_12[8]  ^ tw1[16];
    aa[threadIdx.x].b1 ^= bb.b1 ^ key_12[9]  ^ tw1[17];
    aa[threadIdx.x].b2 ^= bb.b2 ^ key_12[10] ^ tw1[18];
    aa[threadIdx.x].b3 ^= bb.b3 ^ key_12[11] ^ tw1[19];
    aa[threadIdx.x].b4 ^= bb.b4 ^ key_12[12] ^ tw1[20];
    aa[threadIdx.x].b5 ^= bb.b5 ^ key_12[13] ^ tw1[21];
    aa[threadIdx.x].b6 ^= bb.b6 ^ key_12[14] ^ tw1[22];
    aa[threadIdx.x].b7 ^= bb.b7 ^ key_12[15] ^ tw1[23];
    aa[threadIdx.x] = sbox(aa[threadIdx.x]);

    cc.b0 ^= bb.b0 ^ key_12[0] ^ tw1[8];
    cc.b1 ^= bb.b1 ^ key_12[1] ^ tw1[9];
    cc.b2 ^= bb.b2 ^ key_12[2] ^ tw1[10];
    cc.b3 ^= bb.b3 ^ key_12[3] ^ tw1[11];
    cc.b4 ^= bb.b4 ^ key_12[4] ^ tw1[12];
    cc.b5 ^= bb.b5 ^ key_12[5] ^ tw1[13];
    cc.b6 ^= bb.b6 ^ key_12[6] ^ tw1[14];
    cc.b7 ^= bb.b7 ^ key_12[7] ^ tw1[15];
    cc = sbox(cc);

    bb.b0 ^= aa[threadIdx.x].b0 ^ cc.b0 ^ (0 - ((k3456[threadIdx.x] >> 24) & 1)) ^ tw1[0];
    bb.b1 ^= aa[threadIdx.x].b1 ^ cc.b1 ^ (0 - ((k3456[threadIdx.x] >> 25) & 1)) ^ tw1[1];
    bb.b2 ^= aa[threadIdx.x].b2 ^ cc.b2 ^ (0 - ((k3456[threadIdx.x] >> 26) & 1)) ^ tw1[2];
    bb.b3 ^= aa[threadIdx.x].b3 ^ cc.b3 ^ (0 - ((k3456[threadIdx.x] >> 27) & 1)) ^ tw1[3];
    bb.b4 ^= aa[threadIdx.x].b4 ^ cc.b4 ^ (0 - ((k3456[threadIdx.x] >> 28) & 1)) ^ tw1[4];
    bb.b5 ^= aa[threadIdx.x].b5 ^ cc.b5 ^ (0 - ((k3456[threadIdx.x] >> 29) & 1)) ^ tw1[5];
    bb.b6 ^= aa[threadIdx.x].b6 ^ cc.b6 ^ (0 - ((k3456[threadIdx.x] >> 30) & 1)) ^ tw1[6];
    bb.b7 ^= aa[threadIdx.x].b7 ^ cc.b7 ^ (0 - ((k3456[threadIdx.x] >> 31) & 1)) ^ tw1[7];
    bb = sbox(bb);
  }

  int cmp;
  cmp  = cc.b0 ^ ct1[0];
  cmp |= cc.b1 ^ ct1[1];
  cmp |= cc.b2 ^ ct1[2];
  cmp |= cc.b3 ^ ct1[3];
  cmp |= cc.b4 ^ ct1[4];
  cmp |= cc.b5 ^ ct1[5];
  cmp |= cc.b6 ^ ct1[6];
  cmp |= cc.b7 ^ ct1[7];
  cmp |= bb.b0 ^ ct1[8];
  cmp |= bb.b1 ^ ct1[9];
  cmp |= bb.b2 ^ ct1[10];
  cmp |= bb.b3 ^ ct1[11];
  cmp |= bb.b4 ^ ct1[12];
  cmp |= bb.b5 ^ ct1[13];
  cmp |= bb.b6 ^ ct1[14];
  cmp |= bb.b7 ^ ct1[15];
  cmp |= aa[threadIdx.x].b0 ^ ct1[16];
  cmp |= aa[threadIdx.x].b1 ^ ct1[17];
  cmp |= aa[threadIdx.x].b2 ^ ct1[18];
  cmp |= aa[threadIdx.x].b3 ^ ct1[19];
  cmp |= aa[threadIdx.x].b4 ^ ct1[20];
  cmp |= aa[threadIdx.x].b5 ^ ct1[21];
  cmp |= aa[threadIdx.x].b6 ^ ct1[22];
  cmp |= aa[threadIdx.x].b7 ^ ct1[23];
  cmp = ~cmp;

  found[threadIdx.x] = 0;

  __syncthreads();

  /* Put matches in shared memory. */
  if (cmp != 0) {
    int resultp = atomicAdd_block(found, __popc(cmp)) * 2 + 2;
    while (cmp != 0) {
      int low5 = __ffs(cmp) - 1;
      cmp ^= 1 << low5;
      found[resultp] = k3456[threadIdx.x];
      found[resultp + 1] = ((threadIdx.x & 7) << 5) | low5;
      resultp += 2;
    }
  }

  __syncthreads();

  if (found[0] == 0) {
    return;
  }

  /* Get global memory offset for matches found in block. */
  if (threadIdx.x == 0) {
    found[1] = atomicAdd(out, found[0]) * 2 + 1;
  }

  __syncthreads();

  /* Copy matches to global memory. */
  if (threadIdx.x < (found[1] * 2)) {
    int ptr = found[1] + threadIdx.x;
    out[ptr] = found[threadIdx.x + 2];
  }
}

__launch_bounds__(1024, 1)
__global__ void find_candidates(int *ret, int offset) {

  volatile __shared__ int pt1[24];
  volatile __shared__ int pt2[24];
  volatile __shared__ int tw1[64];
  volatile __shared__ int tw2[64];
  volatile __shared__ int key_12[16];
  __shared__ int found[1024];

  if (threadIdx.x < 16) {
    key_12[threadIdx.x] = key_c[threadIdx.x + offset * 16];
  }
  if (threadIdx.x < 24) {
    pt1[threadIdx.x] = pt1_c[threadIdx.x + offset * 24];
    pt2[threadIdx.x] = pt2_c[threadIdx.x + offset * 24];
  }
  if (threadIdx.x < 64) {
    tw1[threadIdx.x] = tw1_c[threadIdx.x + offset * 64];
    tw2[threadIdx.x] = tw2_c[threadIdx.x + offset * 64];
  }

  __syncthreads();

  int key3 = key3_c[blockIdx.x >> 9];

  eightbits aa, bb, cc;

  /* PT1: Round 1. */
  bb.b0 = pt1[8];
  bb.b1 = pt1[9];
  bb.b2 = pt1[10];
  bb.b3 = pt1[11];
  bb.b4 = pt1[12];
  bb.b5 = pt1[13];
  bb.b6 = pt1[14];
  bb.b7 = pt1[15];
  aa.b0 = pt1[16] ^ bb.b0 ^ key_12[8]  ^ tw1[56];
  aa.b1 = pt1[17] ^ bb.b1 ^ key_12[9]  ^ tw1[57];
  aa.b2 = pt1[18] ^ bb.b2 ^ key_12[10] ^ tw1[58];
  aa.b3 = pt1[19] ^ bb.b3 ^ key_12[11] ^ tw1[59];
  aa.b4 = pt1[20] ^ bb.b4 ^ key_12[12] ^ tw1[60];
  aa.b5 = pt1[21] ^ bb.b5 ^ key_12[13] ^ tw1[61];
  aa.b6 = pt1[22] ^ bb.b6 ^ key_12[14] ^ tw1[62];
  aa.b7 = pt1[23] ^ bb.b7 ^ key_12[15] ^ tw1[63];
  aa = sbox(aa);

  cc.b0 = pt1[0]  ^ bb.b0 ^ key_12[0] ^ tw1[48];
  cc.b1 = pt1[1]  ^ bb.b1 ^ key_12[1] ^ tw1[49];
  cc.b2 = pt1[2]  ^ bb.b2 ^ key_12[2] ^ tw1[50];
  cc.b3 = pt1[3]  ^ bb.b3 ^ key_12[3] ^ tw1[51];
  cc.b4 = pt1[4]  ^ bb.b4 ^ key_12[4] ^ tw1[52];
  cc.b5 = pt1[5]  ^ bb.b5 ^ key_12[5] ^ tw1[53];
  cc.b6 = pt1[6]  ^ bb.b6 ^ key_12[6] ^ tw1[54];
  cc.b7 = pt1[7]  ^ bb.b7 ^ key_12[7] ^ tw1[55];
  cc = sbox(cc);

  bb.b0 ^= aa.b0  ^ cc.b0 ^ (0 - ((key3 >> 0) & 1)) ^ tw1[40];
  bb.b1 ^= aa.b1  ^ cc.b1 ^ (0 - ((key3 >> 1) & 1)) ^ tw1[41];
  bb.b2 ^= aa.b2  ^ cc.b2 ^ (0 - ((key3 >> 2) & 1)) ^ tw1[42];
  bb.b3 ^= aa.b3  ^ cc.b3 ^ (0 - ((key3 >> 3) & 1)) ^ tw1[43];
  bb.b4 ^= aa.b4  ^ cc.b4 ^ (0 - ((key3 >> 4) & 1)) ^ tw1[44];
  bb.b5 ^= aa.b5  ^ cc.b5 ^ (0 - ((key3 >> 5) & 1)) ^ tw1[45];
  bb.b6 ^= aa.b6  ^ cc.b6 ^ (0 - ((key3 >> 6) & 1)) ^ tw1[46];
  bb.b7 ^= aa.b7  ^ cc.b7 ^ (0 - ((key3 >> 7) & 1)) ^ tw1[47];
  bb = sbox(bb);

  /* PT1: Round 2. */
  aa.b0 ^= bb.b0 ^ (0 - ((blockIdx.x  >> 1) & 1)) ^ tw1[32];
  aa.b1 ^= bb.b1 ^ (0 - ((blockIdx.x  >> 2) & 1)) ^ tw1[33];
  aa.b2 ^= bb.b2 ^ (0 - ((blockIdx.x  >> 3) & 1)) ^ tw1[34];
  aa.b3 ^= bb.b3 ^ (0 - ((blockIdx.x  >> 4) & 1)) ^ tw1[35];
  aa.b4 ^= bb.b4 ^ (0 - ((blockIdx.x  >> 5) & 1)) ^ tw1[36];
  aa.b5 ^= bb.b5 ^ (0 - ((blockIdx.x  >> 6) & 1)) ^ tw1[37];
  aa.b6 ^= bb.b6 ^ (0 - ((blockIdx.x  >> 7) & 1)) ^ tw1[38];
  aa.b7 ^= bb.b7 ^ (0 - ((blockIdx.x  >> 8) & 1)) ^ tw1[39];
  aa = sbox(aa);

  cc.b0 ^= bb.b0 ^ (0 - ((threadIdx.x >> 3) & 1)) ^ tw1[24];
  cc.b1 ^= bb.b1 ^ (0 - ((threadIdx.x >> 4) & 1)) ^ tw1[25];
  cc.b2 ^= bb.b2 ^ (0 - ((threadIdx.x >> 5) & 1)) ^ tw1[26];
  cc.b3 ^= bb.b3 ^ (0 - ((threadIdx.x >> 6) & 1)) ^ tw1[27];
  cc.b4 ^= bb.b4 ^ (0 - ((threadIdx.x >> 7) & 1)) ^ tw1[28];
  cc.b5 ^= bb.b5 ^ (0 - ((threadIdx.x >> 8) & 1)) ^ tw1[29];
  cc.b6 ^= bb.b6 ^ (0 - ((threadIdx.x >> 9) & 1)) ^ tw1[30];
  cc.b7 ^= bb.b7 ^ (0 -  (blockIdx.x        & 1)) ^ tw1[31];
  cc = sbox(cc);

  bb.b0 ^= aa.b0 ^ cc.b0 ^ 0xaaaaaaaa                     ^ tw1[16];
  bb.b1 ^= aa.b1 ^ cc.b1 ^ 0xcccccccc                     ^ tw1[17];
  bb.b2 ^= aa.b2 ^ cc.b2 ^ 0xf0f0f0f0                     ^ tw1[18];
  bb.b3 ^= aa.b3 ^ cc.b3 ^ 0xff00ff00                     ^ tw1[19];
  bb.b4 ^= aa.b4 ^ cc.b4 ^ 0xffff0000                     ^ tw1[20];
  bb.b5 ^= aa.b5 ^ cc.b5 ^ (0 - ((threadIdx.x >> 0) & 1)) ^ tw1[21];
  bb.b6 ^= aa.b6 ^ cc.b6 ^ (0 - ((threadIdx.x >> 1) & 1)) ^ tw1[22];
  bb.b7 ^= aa.b7 ^ cc.b7 ^ (0 - ((threadIdx.x >> 2) & 1)) ^ tw1[23];
  bb = sbox(bb);

  /* PT1: Round 3c. */
  cc.b0 ^= bb.b0 ^ key_12[8]  ^ tw1[0];
  cc.b1 ^= bb.b1 ^ key_12[9]  ^ tw1[1];
  cc.b2 ^= bb.b2 ^ key_12[10] ^ tw1[2];
  cc.b3 ^= bb.b3 ^ key_12[11] ^ tw1[3];
  cc.b4 ^= bb.b4 ^ key_12[12] ^ tw1[4];
  cc.b5 ^= bb.b5 ^ key_12[13] ^ tw1[5];
  cc.b6 ^= bb.b6 ^ key_12[14] ^ tw1[6];
  cc.b7 ^= bb.b7 ^ key_12[15] ^ tw1[7];
  cc = sbox(cc);

  eightbits xx;
  xx.b0 = cc.b0 ^ tw1[24] ^ tw2[24];
  xx.b1 = cc.b1 ^ tw1[25] ^ tw2[25];
  xx.b2 = cc.b2 ^ tw1[26] ^ tw2[26];
  xx.b3 = cc.b3 ^ tw1[27] ^ tw2[27];
  xx.b4 = cc.b4 ^ tw1[28] ^ tw2[28];
  xx.b5 = cc.b5 ^ tw1[29] ^ tw2[29];
  xx.b6 = cc.b6 ^ tw1[30] ^ tw2[30];
  xx.b7 = cc.b7 ^ tw1[31] ^ tw2[31];

  /* PT2: Round 1. */
  bb.b0 = pt2[8];
  bb.b1 = pt2[9];
  bb.b2 = pt2[10];
  bb.b3 = pt2[11];
  bb.b4 = pt2[12];
  bb.b5 = pt2[13];
  bb.b6 = pt2[14];
  bb.b7 = pt2[15];
  aa.b0 = pt2[16] ^ bb.b0 ^ key_12[8]  ^ tw2[56];
  aa.b1 = pt2[17] ^ bb.b1 ^ key_12[9]  ^ tw2[57];
  aa.b2 = pt2[18] ^ bb.b2 ^ key_12[10] ^ tw2[58];
  aa.b3 = pt2[19] ^ bb.b3 ^ key_12[11] ^ tw2[59];
  aa.b4 = pt2[20] ^ bb.b4 ^ key_12[12] ^ tw2[60];
  aa.b5 = pt2[21] ^ bb.b5 ^ key_12[13] ^ tw2[61];
  aa.b6 = pt2[22] ^ bb.b6 ^ key_12[14] ^ tw2[62];
  aa.b7 = pt2[23] ^ bb.b7 ^ key_12[15] ^ tw2[63];
  aa = sbox(aa);

  cc.b0 = pt2[0]  ^ bb.b0 ^ key_12[0] ^ tw2[48];
  cc.b1 = pt2[1]  ^ bb.b1 ^ key_12[1] ^ tw2[49];
  cc.b2 = pt2[2]  ^ bb.b2 ^ key_12[2] ^ tw2[50];
  cc.b3 = pt2[3]  ^ bb.b3 ^ key_12[3] ^ tw2[51];
  cc.b4 = pt2[4]  ^ bb.b4 ^ key_12[4] ^ tw2[52];
  cc.b5 = pt2[5]  ^ bb.b5 ^ key_12[5] ^ tw2[53];
  cc.b6 = pt2[6]  ^ bb.b6 ^ key_12[6] ^ tw2[54];
  cc.b7 = pt2[7]  ^ bb.b7 ^ key_12[7] ^ tw2[55];
  cc = sbox(cc);

  bb.b0 ^= aa.b0  ^ cc.b0 ^ (0 - ((key3 >> 0) & 1)) ^ tw2[40];
  bb.b1 ^= aa.b1  ^ cc.b1 ^ (0 - ((key3 >> 1) & 1)) ^ tw2[41];
  bb.b2 ^= aa.b2  ^ cc.b2 ^ (0 - ((key3 >> 2) & 1)) ^ tw2[42];
  bb.b3 ^= aa.b3  ^ cc.b3 ^ (0 - ((key3 >> 3) & 1)) ^ tw2[43];
  bb.b4 ^= aa.b4  ^ cc.b4 ^ (0 - ((key3 >> 4) & 1)) ^ tw2[44];
  bb.b5 ^= aa.b5  ^ cc.b5 ^ (0 - ((key3 >> 5) & 1)) ^ tw2[45];
  bb.b6 ^= aa.b6  ^ cc.b6 ^ (0 - ((key3 >> 6) & 1)) ^ tw2[46];
  bb.b7 ^= aa.b7  ^ cc.b7 ^ (0 - ((key3 >> 7) & 1)) ^ tw2[47];
  bb = sbox(bb);

  /* PT2: Round 2. */
  aa.b0 ^= bb.b0 ^ (0 - ((blockIdx.x  >> 1) & 1)) ^ tw2[32];
  aa.b1 ^= bb.b1 ^ (0 - ((blockIdx.x  >> 2) & 1)) ^ tw2[33];
  aa.b2 ^= bb.b2 ^ (0 - ((blockIdx.x  >> 3) & 1)) ^ tw2[34];
  aa.b3 ^= bb.b3 ^ (0 - ((blockIdx.x  >> 4) & 1)) ^ tw2[35];
  aa.b4 ^= bb.b4 ^ (0 - ((blockIdx.x  >> 5) & 1)) ^ tw2[36];
  aa.b5 ^= bb.b5 ^ (0 - ((blockIdx.x  >> 6) & 1)) ^ tw2[37];
  aa.b6 ^= bb.b6 ^ (0 - ((blockIdx.x  >> 7) & 1)) ^ tw2[38];
  aa.b7 ^= bb.b7 ^ (0 - ((blockIdx.x  >> 8) & 1)) ^ tw2[39];
  aa = sbox(aa);

  cc.b0 ^= bb.b0 ^ (0 - ((threadIdx.x >> 3) & 1)) ^ tw2[24];
  cc.b1 ^= bb.b1 ^ (0 - ((threadIdx.x >> 4) & 1)) ^ tw2[25];
  cc.b2 ^= bb.b2 ^ (0 - ((threadIdx.x >> 5) & 1)) ^ tw2[26];
  cc.b3 ^= bb.b3 ^ (0 - ((threadIdx.x >> 6) & 1)) ^ tw2[27];
  cc.b4 ^= bb.b4 ^ (0 - ((threadIdx.x >> 7) & 1)) ^ tw2[28];
  cc.b5 ^= bb.b5 ^ (0 - ((threadIdx.x >> 8) & 1)) ^ tw2[29];
  cc.b6 ^= bb.b6 ^ (0 - ((threadIdx.x >> 9) & 1)) ^ tw2[30];
  cc.b7 ^= bb.b7 ^ (0 -  (blockIdx.x        & 1)) ^ tw2[31];
  cc = sbox(cc);

  bb.b0 ^= aa.b0 ^ cc.b0 ^ 0xaaaaaaaa                     ^ tw2[16];
  bb.b1 ^= aa.b1 ^ cc.b1 ^ 0xcccccccc                     ^ tw2[17];
  bb.b2 ^= aa.b2 ^ cc.b2 ^ 0xf0f0f0f0                     ^ tw2[18];
  bb.b3 ^= aa.b3 ^ cc.b3 ^ 0xff00ff00                     ^ tw2[19];
  bb.b4 ^= aa.b4 ^ cc.b4 ^ 0xffff0000                     ^ tw2[20];
  bb.b5 ^= aa.b5 ^ cc.b5 ^ (0 - ((threadIdx.x >> 0) & 1)) ^ tw2[21];
  bb.b6 ^= aa.b6 ^ cc.b6 ^ (0 - ((threadIdx.x >> 1) & 1)) ^ tw2[22];
  bb.b7 ^= aa.b7 ^ cc.b7 ^ (0 - ((threadIdx.x >> 2) & 1)) ^ tw2[23];
  bb = sbox(bb);

  /* PT2: Round 3c. */
  cc.b0 ^= bb.b0 ^ key_12[8]  ^ tw2[0];
  cc.b1 ^= bb.b1 ^ key_12[9]  ^ tw2[1];
  cc.b2 ^= bb.b2 ^ key_12[10] ^ tw2[2];
  cc.b3 ^= bb.b3 ^ key_12[11] ^ tw2[3];
  cc.b4 ^= bb.b4 ^ key_12[12] ^ tw2[4];
  cc.b5 ^= bb.b5 ^ key_12[13] ^ tw2[5];
  cc.b6 ^= bb.b6 ^ key_12[14] ^ tw2[6];
  cc.b7 ^= bb.b7 ^ key_12[15] ^ tw2[7];
  cc = sbox(cc);

  int rr;
  rr  = cc.b0 ^ xx.b0;
  rr |= cc.b1 ^ xx.b1;
  rr |= cc.b2 ^ xx.b2;
  rr |= cc.b3 ^ xx.b3;
  rr |= cc.b4 ^ xx.b4;
  rr |= cc.b5 ^ xx.b5;
  rr |= cc.b6 ^ xx.b6;
  rr |= cc.b7 ^ xx.b7;
  rr = ~rr;

  found[threadIdx.x] = 0;

  __syncthreads();

  if (rr != 0) {
    int ptr = atomicAdd_block(found, __popc(rr));
    int k3456 = (key3 << 24) | ((blockIdx.x & 0x1ff) << 15) | (threadIdx.x << 5);
    while (rr != 0) {
      int low5 = __ffs(rr) - 1;
      rr ^= 1 << low5;
      found[ptr + 2] = k3456 | low5;
      ptr += 1;
    }
  }

  __syncthreads();

  if (found[0] == 0) {
    return;
  }

  if (threadIdx.x == 0) {
    found[1] = atomicAdd(ret, found[0]) + 1;
  }

  __syncthreads();

  if (threadIdx.x < found[0]) {
    int ptr = found[1] + threadIdx.x;
    ret[ptr] = found[threadIdx.x + 2];
  }
}

/* Host functions. */

void list_cuda_devices() {
  int count = -1;
  cudaError_t err;
  err = cudaGetDeviceCount(&count);
  if (err == 30 || count == 0) {
    printf("No CUDA devices found.\n");
    return;
  }
  if (err != 0) {
    fprintf(stderr, "Error: cudaGetDeviceCount returned error %d.\n", err);
    return;
  }
  for (int i = 0; i < count; i++) {
    cudaDeviceProp prop;
    err = cudaGetDeviceProperties(&prop, i);
    if (err != 0) {
      printf("Error when getting properties for device %d.\n", i);
    } else {
      printf("CUDA Device %d: %s\n", i, prop.name);
    }
  }
}

int get_num_cuda_devices() {
  int count;
  cudaError_t err;
  err = cudaGetDeviceCount(&count);
  if (err == 30) {
    return 0;
  }
  if (err != 0) {
    return -1;
  }
  return count;
}

#define CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem)\
  if (err != cudaSuccess) {\
    fprintf(stderr, "CUDA error. (%s:%d)\n", __FILE__, __LINE__);\
    if (stream != NULL) { cudaStreamDestroy(stream); }\
    if (ret != NULL) { cudaFreeHost(ret); }\
    if (dev_mem != NULL) { cudaFree(dev_mem); }\
    return;\
  }

void cuda_fast(worker_param_t params, uint32_t threadid, uint32_t cuda_device) {

  uint32_t *ret = NULL;
  int32_t *dev_mem = NULL;
  int32_t *dev_mem2 = NULL;
  cudaStream_t stream = NULL;

  cudaError_t err = cudaSetDevice(cuda_device);
  CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);

  /* Allocate host memory. */
  err = cudaHostAlloc(&ret, sizeof(int32_t) * 0x2000000, cudaHostAllocDefault);
  CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);
  assert(ret != NULL);

  /* Allocate device memory. */

  err = cudaMalloc(&dev_mem, sizeof(int32_t) * 0x2000000);
  CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);
  err = cudaMalloc(&dev_mem2, sizeof(int32_t) * 1000);
  CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);
  assert(dev_mem != NULL);
  assert(dev_mem2 != NULL);

  err = cudaStreamCreate(&stream);
  CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);

  uint32_t k12;
  pair_t *pair;
  int32_t hi_key_bits[24];
  int32_t pt1_bits[24];
  int32_t pt2_bits[24];
  int32_t ct1_bits[24];
  int32_t tw1_bits[64];
  int32_t tw2_bits[64];

  while (!g_exit && get_next_678(threadid, &k12, &pair)) {

    /* Set plaintext, tweak and high key bits. */
    for (int bit = 0; bit < 24; bit++) {
      hi_key_bits[bit] = 0 - ((k12 >> bit) & 1);
      pt1_bits[bit]    = 0 - ((pair->t1.pt >> bit) & 1);
      pt2_bits[bit]    = 0 - ((pair->t2.pt >> bit) & 1);
      ct1_bits[bit]    = 0 - ((pair->t1.ct >> bit) & 1);
    }
    for (int bit = 0; bit < 64; bit++) {
      tw1_bits[bit] = 0 - ((pair->t1.tw >> bit) & 1);
      tw2_bits[bit] = 0 - ((pair->t2.tw >> bit) & 1);
    }

    err = cudaMemcpyToSymbolAsync(key_c, hi_key_bits, sizeof(int32_t) * 24, 0,
        cudaMemcpyHostToDevice, stream);
    CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);
    err = cudaMemcpyToSymbolAsync(pt1_c, pt1_bits,    sizeof(int32_t) * 24, 0,
        cudaMemcpyHostToDevice, stream);
    CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);
    err = cudaMemcpyToSymbolAsync(pt2_c, pt2_bits,    sizeof(int32_t) * 24, 0,
        cudaMemcpyHostToDevice, stream);
    CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);
    err = cudaMemcpyToSymbolAsync(ct1_c, ct1_bits,    sizeof(int32_t) * 24, 0,
        cudaMemcpyHostToDevice, stream);
    CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);
    err = cudaMemcpyToSymbolAsync(tw1_c, tw1_bits,    sizeof(int32_t) * 64, 0,
        cudaMemcpyHostToDevice, stream);
    CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);
    err = cudaMemcpyToSymbolAsync(tw2_c, tw2_bits,    sizeof(int32_t) * 64, 0,
        cudaMemcpyHostToDevice, stream);
    CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);
    err = cudaMemcpyToSymbolAsync(key3_c, pair->k3,   sizeof(int32_t) * 256, 0,
        cudaMemcpyHostToDevice, stream);

    err = cudaMemsetAsync(dev_mem, 0, sizeof(int32_t) * 1, stream);
    CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);
    err = cudaMemsetAsync(dev_mem2, 0, sizeof(int32_t) * 1, stream);
    CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);

    find_candidates<<<512 * pair->num_k3, 1024, 0, stream>>>(dev_mem, 0);
    err = cudaMemcpyAsync(ret, dev_mem, sizeof(int32_t) * 1, cudaMemcpyDefault, stream);
    CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);

    err = cudaStreamSynchronize(stream);
    CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);

    int num_blocks = (ret[0] + 129) / 128;
    switch (params.nrounds) {
      case 6:
        test_candidates<6><<<num_blocks, 1024, 0, stream>>>(dev_mem, dev_mem2, ret[0], 0);
        break;
      case 7:
        test_candidates<7><<<num_blocks, 1024, 0, stream>>>(dev_mem, dev_mem2, ret[0], 0);
        break;
      case 8:
        test_candidates<8><<<num_blocks, 1024, 0, stream>>>(dev_mem, dev_mem2, ret[0], 0);
        break;
      default:
        assert(0);
    }
    err = cudaMemcpyAsync(ret, dev_mem2, sizeof(int32_t) * 1000, cudaMemcpyDefault, stream);
    CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);

    err = cudaStreamSynchronize(stream);
    CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);

    for (int i = 0; i < ret[0]; i++) {
      uint64_t key = ((uint64_t)k12 << 40) | ((uint64_t)ret[i * 2 + 1] << 8) | ret[i * 2 + 2];
      if (test_key(params.nrounds, key, params.tuples, params.num_tuples)) {
        found_key(key);
      }
    }
  }

  cudaDeviceSynchronize();
  cudaProfilerStop();
  cudaStreamDestroy(stream);
  cudaFreeHost(ret);
  cudaFree(dev_mem);
  cudaFree(dev_mem2);
  cudaDeviceReset();
}

void cuda_brute(worker_param_t params, uint32_t threadid, uint32_t cuda_device, int rounds) {
  uint32_t *ret = NULL;
  int32_t *dev_mem = NULL;
  cudaStream_t stream = NULL;

  cudaError_t err = cudaSetDevice(cuda_device);
  CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);

  /* Allocate host memory. */
  err = cudaHostAlloc(&ret, sizeof(int32_t) * 2000, cudaHostAllocDefault);
  CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);
  assert(ret != NULL);

  /* Allocate device memory. */
  err = cudaMalloc(&dev_mem, sizeof(int32_t) * 2000);
  CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);
  assert(dev_mem != NULL);

  err = cudaStreamCreate(&stream);
  CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);

  uint32_t k12;
  pair_t *pair;
  int32_t hi_key_bits[24];
  int32_t pt1_bits[24];
  int32_t ct1_bits[24];
  int32_t tw1_bits[64];

  while (!g_exit && get_next_678(threadid, &k12, &pair)) {
    for (int k3 = 0; !g_exit && k3 < 0x100; k3++) {
      uint64_t k123 = (k12 << 8) | k3;
      uint32_t pt1p = enc_one_round_3(pair->t1.pt, k123 ^ (pair->t1.tw >> 40));
      uint32_t ct1p = pair->t1.ct;
      if (rounds == 8 || rounds == 15) {
        int shift = rounds == 8 ? 0 : 24;
        ct1p = dec_one_round_3(pair->t1.ct, k123 ^ ((pair->t1.tw >> shift) & 0xffffff));
      }
      uint32_t ca = ct1p >> 16;
      uint32_t cb = (ct1p >> 8) & 0xff;
      uint32_t cc = ct1p & 0xff;
      uint32_t pb = g_sbox_dec[cb] ^ ca ^ cc;
      uint32_t pc = g_sbox_dec[cc];
      uint32_t pa = g_sbox_dec[ca];
      ct1p = (pa << 16) | (pb << 8) | pc;

      /* Set plaintext, tweak and high key bits. */
      for (int bit = 0; bit < 24; bit++) {
        hi_key_bits[bit] = 0 - ((k123 >> bit) & 1);
        pt1_bits[bit]    = 0 - ((pt1p >> bit) & 1);
        ct1_bits[bit]    = 0 - ((ct1p >> bit) & 1);
      }
      for (int bit = 0; bit < 64; bit++) {
        tw1_bits[bit] = 0 - ((pair->t1.tw >> bit) & 1);
      }

      err = cudaMemcpyToSymbolAsync(key_c, hi_key_bits, sizeof(int32_t) * 24, 0,
          cudaMemcpyHostToDevice, stream);
      CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);
      err = cudaMemcpyToSymbolAsync(pt1_c, pt1_bits,    sizeof(int32_t) * 24, 0,
          cudaMemcpyHostToDevice, stream);
      CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);
      err = cudaMemcpyToSymbolAsync(ct1_c, ct1_bits,    sizeof(int32_t) * 24, 0,
          cudaMemcpyHostToDevice, stream);
      CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);
      err = cudaMemcpyToSymbolAsync(tw1_c, tw1_bits,    sizeof(int32_t) * 64, 0,
          cudaMemcpyHostToDevice, stream);
      CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);

      err = cudaMemsetAsync(dev_mem, 0, sizeof(int32_t) * 2000, stream);
      CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);

      switch (rounds) {
        case 6:
          brute_force<6><<<0x20000, 1024, 0, stream>>>(dev_mem, 0);
          break;
        case 7:
          brute_force<7><<<0x20000, 1024, 0, stream>>>(dev_mem, 0);
          break;
        case 8:
          brute_force<7><<<0x20000, 1024, 0, stream>>>(dev_mem, 0);
          break;
        case 9:
          brute_force<9><<<0x20000, 1024, 0, stream>>>(dev_mem, 0);
          break;
        case 10:
          brute_force<10><<<0x20000, 1024, 0, stream>>>(dev_mem, 0);
          break;
        case 11:
          brute_force<11><<<0x20000, 1024, 0, stream>>>(dev_mem, 0);
          break;
        case 12:
          brute_force<12><<<0x20000, 1024, 0, stream>>>(dev_mem, 0);
          break;
        case 13:
          brute_force<13><<<0x20000, 1024, 0, stream>>>(dev_mem, 0);
          break;
        case 14:
          brute_force<14><<<0x20000, 1024, 0, stream>>>(dev_mem, 0);
          break;
        case 15:
          brute_force<14><<<0x20000, 1024, 0, stream>>>(dev_mem, 0);
          break;
        case 16:
          brute_force<16><<<0x20000, 1024, 0, stream>>>(dev_mem, 0);
          break;
      }

      err = cudaMemcpyAsync(ret, dev_mem, sizeof(int32_t) * 2000, cudaMemcpyDefault, stream);
      CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);

      err = cudaStreamSynchronize(stream);
      CUDA_FAST_RETURN_ON_ERROR(err, stream, ret, dev_mem);

      uint64_t bkey = k123 << 32;
      for (int i = 0; i < ret[0]; i++) {
        uint64_t key = bkey | (ret[i * 2 + 1] << 5);
        uint32_t xx = ~ret[i * 2 + 2];
        while (xx != 0) {
          uint64_t lkey = (__builtin_ffs(xx) - 1) | key;
          if (test_key(params.nrounds, lkey, params.tuples, params.num_tuples)) {
            found_key(lkey);
          }
          xx ^= 1 << (lkey & 0x1f);
        }
      }
    }
  }

  cudaDeviceSynchronize();
  cudaProfilerStop();
  cudaStreamDestroy(stream);
  cudaFreeHost(ret);
  cudaFree(dev_mem);
  cudaDeviceReset();
}
