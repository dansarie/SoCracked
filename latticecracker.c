/* latticecracker
   Attacks two, three or four rounds of the Lattice algorithm as specified in MIL-STD-188-141 and
   recovers all candidate keys in 2^10 - 2^12 time for two rounds, 2^17 time for three rounds, and
   2^33 time for four rounds of encryption.
   Copyright (C) 2016 Marcus Dansarie <marcus@dansarie.se>

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
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Lookup tables for the Lattice algorithm s-box. */
uint8_t g_sbox_dec[256];
const uint8_t g_sbox_enc[] = {0x9c, 0xf2, 0x14, 0xc1, 0x8e, 0xcb, 0xb2, 0x65,
                              0x97, 0x7a, 0x60, 0x17, 0x92, 0xf9, 0x78, 0x41,
                              0x07, 0x4c, 0x67, 0x6d, 0x66, 0x4a, 0x30, 0x7d,
                              0x53, 0x9d, 0xb5, 0xbc, 0xc3, 0xca, 0xf1, 0x04,
                              0x03, 0xec, 0xd0, 0x38, 0xb0, 0xed, 0xad, 0xc4,
                              0xdd, 0x56, 0x42, 0xbd, 0xa0, 0xde, 0x1b, 0x81,
                              0x55, 0x44, 0x5a, 0xe4, 0x50, 0xdc, 0x43, 0x63,
                              0x09, 0x5c, 0x74, 0xcf, 0x0e, 0xab, 0x1d, 0x3d,
                              0x6b, 0x02, 0x5d, 0x28, 0xe7, 0xc6, 0xee, 0xb4,
                              0xd9, 0x7c, 0x19, 0x3e, 0x5e, 0x6c, 0xd6, 0x6e,
                              0x2a, 0x13, 0xa5, 0x08, 0xb9, 0x2d, 0xbb, 0xa2,
                              0xd4, 0x96, 0x39, 0xe0, 0xba, 0xd7, 0x82, 0x33,
                              0x0d, 0x5f, 0x26, 0x16, 0xfe, 0x22, 0xaf, 0x00,
                              0x11, 0xc8, 0x9e, 0x88, 0x8b, 0xa1, 0x7b, 0x87,
                              0x27, 0xe6, 0xc7, 0x94, 0xd1, 0x5b, 0x9b, 0xf0,
                              0x9f, 0xdb, 0xe1, 0x8d, 0xd2, 0x1f, 0x6a, 0x90,
                              0xf4, 0x18, 0x91, 0x59, 0x01, 0xb1, 0xfc, 0x34,
                              0x3c, 0x37, 0x47, 0x29, 0xe2, 0x64, 0x69, 0x24,
                              0x0a, 0x2f, 0x73, 0x71, 0xa9, 0x84, 0x8c, 0xa8,
                              0xa3, 0x3b, 0xe3, 0xe9, 0x58, 0x80, 0xa7, 0xd3,
                              0xb7, 0xc2, 0x1c, 0x95, 0x1e, 0x4d, 0x4f, 0x4e,
                              0xfb, 0x76, 0xfd, 0x99, 0xc5, 0xc9, 0xe8, 0x2e,
                              0x8a, 0xdf, 0xf5, 0x49, 0xf3, 0x6f, 0x8f, 0xe5,
                              0xeb, 0xf6, 0x25, 0xd5, 0x31, 0xc0, 0x57, 0x72,
                              0xaa, 0x46, 0x68, 0x0b, 0x93, 0x89, 0x83, 0x70,
                              0xef, 0xa4, 0x85, 0xf8, 0x0f, 0xb3, 0xac, 0x10,
                              0x62, 0xcc, 0x61, 0x40, 0xf7, 0xfa, 0x52, 0x7f,
                              0xff, 0x32, 0x45, 0x20, 0x79, 0xce, 0xea, 0xbe,
                              0xcd, 0x15, 0x21, 0x23, 0xd8, 0xb6, 0x0c, 0x3f,
                              0x54, 0x1a, 0xbf, 0x98, 0x48, 0x3a, 0x75, 0x77,
                              0x2b, 0xae, 0x36, 0xda, 0x7e, 0x86, 0x35, 0x51,
                              0x05, 0x12, 0xb8, 0xa6, 0x9a, 0x2c, 0x06, 0x4b};

pthread_mutex_t g_next_lock;
pthread_mutex_t g_write_lock;
pthread_mutex_t g_threadcount_lock;
uint64_t g_keysfound = 0;
uint32_t g_threadcount = 0;    /* Number of working threads. */
uint32_t g_next = 0;           /* Next work unit. (Value of key bytes 1 and 2.) */
FILE *g_outfp = NULL;          /* Pointer to output file. */

/* Known plaintexts, ciphertexts and tweaks. If only two are used g_pt3 = g_tw3 = g_ct3 = -1. */
uint32_t g_pt1 = (uint32_t)-1;
uint32_t g_pt2 = (uint32_t)-1;
uint32_t g_pt3 = (uint32_t)-1;
uint64_t g_tw1 = (uint64_t)-1;
uint64_t g_tw2 = (uint64_t)-1;
uint64_t g_tw3 = (uint64_t)-1;
uint32_t g_ct1 = (uint32_t)-1;
uint32_t g_ct2 = (uint32_t)-1;
uint32_t g_ct3 = (uint32_t)-1;

/* Do one round of encryption with the Lattice algorithm.
   pt   Plaintext (24 bits).
   rkey Round key, i.e. the three key bytes xored with three bytes of tweak. */
static inline uint32_t enc_one_round(uint32_t pt, uint32_t rkey);

/* Do one round of decryption with the Lattice algorithm.
   ct   Ciphertext (24 bits).
   rkey Round key, i.e. the three key bytes xored with three bytes of tweak. */
static inline uint32_t dec_one_round(uint32_t ct, uint32_t rkey);

/* Do three rounds of encryption with the Lattice algorithm.
   rounds Number of rounds (1-8).
   pt     Plaintext (24 bits).
   key    Encryption key (56 bits).
   tweak  Tweak (64 bits). */
static inline uint32_t encrypt_lattice(uint8_t rounds, uint32_t pt, uint64_t key, uint64_t tweak);

/* Returns the next work unit, i.e. the next value of key bytes 1 and 2.
   A return value of 0x10000 indicates that there are no more work units available and that the
   thread should stop. */
uint32_t get_next();

/* The cracking functions. The argument is not used. */
void *crack4(void *param);

static inline uint32_t enc_one_round(uint32_t pt, uint32_t rkey) {
  uint8_t pa = pt >> 16;
  uint8_t pb = (pt >> 8) & 0xff;
  uint8_t pc = pt & 0xff;
  uint8_t ka = rkey >> 16;
  uint8_t kb = (rkey >> 8) & 0xff;
  uint8_t kc = rkey & 0xff;
  uint8_t ca = g_sbox_enc[pa ^ pb ^ ka];
  uint8_t cc = g_sbox_enc[pc ^ pb ^ kb];
  uint8_t cb = g_sbox_enc[ca ^ pb ^ cc ^ kc];
  return (ca << 16) | (cb << 8) | cc;
}

static inline uint32_t dec_one_round(uint32_t ct, uint32_t rkey) {
  uint8_t ca = ct >> 16;
  uint8_t cb = (ct >> 8) & 0xff;
  uint8_t cc = ct & 0xff;
  uint8_t ka = rkey >> 16;
  uint8_t kb = (rkey >> 8) & 0xff;
  uint8_t kc = rkey & 0xff;
  uint8_t pb = g_sbox_dec[cb] ^ ca ^ cc ^ kc;
  uint8_t pc = g_sbox_dec[cc] ^ pb ^ kb;
  uint8_t pa = g_sbox_dec[ca] ^ pb ^ ka;
  return (pa << 16) | (pb << 8) | pc;
}

static inline uint32_t encrypt_lattice(uint8_t rounds, uint32_t pt, uint64_t key, uint64_t tweak) {
  uint32_t ct = pt;
  for (uint8_t round = 0; round < rounds; round++) {
    uint32_t rkey = (key >> 32) ^ (tweak >> 40);
    tweak = (tweak << 24) | (tweak >> 40);
    key = ((key << 24) | (key >> 32)) & 0x00ffffffffffffff;
    ct = enc_one_round(ct, rkey);
  }
  return ct;
}

uint32_t get_next() {
  pthread_mutex_lock(&g_next_lock);
  if (g_next >= 0x10000) {
    pthread_mutex_unlock(&g_next_lock);
    return 0x10000;
  }
  uint32_t ret = g_next;
  g_next += 1;
  pthread_mutex_unlock(&g_next_lock);
  return ret;
}

void crack2() {
  const uint8_t tw11 = (g_tw1 >> 56) & 0xff;
  const uint8_t tw12 = (g_tw1 >> 48) & 0xff;
  const uint8_t tw13 = (g_tw1 >> 40) & 0xff;
  const uint8_t tw14 = (g_tw1 >> 32) & 0xff;
  const uint8_t tw15 = (g_tw1 >> 24) & 0xff;
  const uint8_t tw16 = (g_tw1 >> 16) & 0xff;
  const uint8_t tw21 = (g_tw2 >> 56) & 0xff;
  const uint8_t tw22 = (g_tw2 >> 48) & 0xff;
  const uint8_t tw23 = (g_tw2 >> 40) & 0xff;
  const uint8_t tw24 = (g_tw2 >> 32) & 0xff;
  const uint8_t tw25 = (g_tw2 >> 24) & 0xff;
  const uint8_t tw26 = (g_tw2 >> 16) & 0xff;
  const uint8_t b1 = ((g_pt1 >> 8) & 0xff) ^ tw13;
  const uint8_t a1 = (((g_pt1 >> 16) ^ (g_pt1 >> 8)) & 0xff) ^ tw11;
  const uint8_t c1 = ((g_pt1 ^ (g_pt1 >> 8)) & 0xff) ^ tw12;
  const uint8_t b2 = ((g_pt2 >> 8) & 0xff) ^ tw23;
  const uint8_t a2 = (((g_pt2 >> 16) ^ (g_pt2 >> 8)) & 0xff) ^ tw21;
  const uint8_t c2 = ((g_pt2 ^ (g_pt2 >> 8)) & 0xff) ^ tw22;
  const uint8_t app1 = (g_ct1 >> 16) & 0xff;
  const uint8_t app2 = (g_ct2 >> 16) & 0xff;
  const uint8_t cpp1 = g_ct1 & 0xff;
  const uint8_t cpp2 = g_ct2 & 0xff;
  const uint8_t bpp1 = g_sbox_dec[(g_ct1 >> 8) & 0xff] ^ app1 ^ cpp1 ^ tw16;
  const uint8_t bpp2 = g_sbox_dec[(g_ct2 >> 8) & 0xff] ^ app2 ^ cpp2 ^ tw26;
  const uint8_t sapp1 = g_sbox_dec[app1] ^ tw14;
  const uint8_t sapp2 = g_sbox_dec[app2] ^ tw24;
  const uint8_t scpp1 = g_sbox_dec[cpp1] ^ tw15;
  const uint8_t scpp2 = g_sbox_dec[cpp2] ^ tw25;
  const uint8_t da = sapp1 ^ sapp2 ^ bpp1 ^ bpp2;
  const uint8_t dc = scpp1 ^ scpp2 ^ bpp1 ^ bpp2;
  uint8_t k1[256];
  uint8_t k2[256];
  uint16_t k1p = 0;
  uint16_t k2p = 0;
  for (uint16_t k = 0; k < 256; k++) {
    if ((g_sbox_enc[a1 ^ k] ^ g_sbox_enc[a2 ^ k]) == da) {
      k1[k1p++] = k;
    }
    if ((g_sbox_enc[c1 ^ k] ^ g_sbox_enc[c2 ^ k]) == dc) {
      k2[k2p++] = k;
    }
  }
  for (uint16_t i = 0; i < k1p; i++) {
    const uint8_t ap1 = g_sbox_enc[a1 ^ k1[i]];
    const uint8_t ap2 = g_sbox_enc[a2 ^ k1[i]];
    for (uint16_t k = 0; k < k2p; k++) {
      const uint8_t cp1 = g_sbox_enc[c1 ^ k2[k]];
      const uint8_t cp2 = g_sbox_enc[c2 ^ k2[k]];
      for (uint16_t k3 = 0; k3 < 256; k3++) {
        const uint8_t bp1 = g_sbox_enc[b1 ^ ap1 ^ cp1 ^ k3];
        const uint8_t bp2 = g_sbox_enc[b2 ^ ap2 ^ cp2 ^ k3];
        const uint8_t k41 = bp1 ^ ap1 ^ sapp1;
        const uint8_t k42 = bp2 ^ ap2 ^ sapp2;
        const uint8_t k51 = bp1 ^ cp1 ^ scpp1;
        const uint8_t k52 = bp2 ^ cp2 ^ scpp2;
        const uint8_t k6 = bp1 ^ bpp1;
        if (k41 == k42 && k51 == k52) {
          uint64_t key = (uint64_t)k1[i] << 48 | (uint64_t)k2[k] << 40 | (uint64_t)k3 << 32
              | (uint64_t)k41 << 24 | (uint64_t)k51 << 16 | (uint64_t)k6 << 8;
          if (g_pt3 == (uint32_t)-1 || encrypt_lattice(2, g_pt3, key, g_tw3) == g_ct3) {
            fprintf(g_outfp, "%014" PRIx64 "\n", key);
            g_keysfound += 1;
          }
        }
      }
    }
  }
  if (g_keysfound == 0) {
    printf("No keys found.\n");
  } else if (g_keysfound == 1) {
    printf("1 key found.\n");
  } else {
    printf("%" PRIu64 " keys found.\n", g_keysfound);
  }
}

void crack3() {
  const uint8_t tw11 = (g_tw1 >> 56) & 0xff;
  const uint8_t tw12 = (g_tw1 >> 48) & 0xff;
  const uint8_t tw13 = (g_tw1 >> 40) & 0xff;
  const uint8_t tw14 = (g_tw1 >> 32) & 0xff;
  const uint8_t tw15 = (g_tw1 >> 24) & 0xff;
  const uint8_t tw16 = (g_tw1 >> 16) & 0xff;
  const uint8_t tw17 = (g_tw1 >> 8) & 0xff;
  const uint8_t tw18 = g_tw1 & 0xff;
  const uint8_t tw21 = (g_tw2 >> 56) & 0xff;
  const uint8_t tw22 = (g_tw2 >> 48) & 0xff;
  const uint8_t tw23 = (g_tw2 >> 40) & 0xff;
  const uint8_t tw24 = (g_tw2 >> 32) & 0xff;
  const uint8_t tw25 = (g_tw2 >> 24) & 0xff;
  const uint8_t tw26 = (g_tw2 >> 16) & 0xff;
  const uint8_t tw27 = (g_tw2 >> 8) & 0xff;
  const uint8_t tw28 = g_tw2 & 0xff;
  const uint8_t b1 = ((g_pt1 >> 8) & 0xff) ^ tw13;
  const uint8_t a1 = (((g_pt1 >> 16) ^ (g_pt1 >> 8)) & 0xff) ^ tw11;
  const uint8_t c1 = ((g_pt1 ^ (g_pt1 >> 8)) & 0xff) ^ tw12;
  const uint8_t b2 = ((g_pt2 >> 8) & 0xff) ^ tw23;
  const uint8_t a2 = (((g_pt2 >> 16) ^ (g_pt2 >> 8)) & 0xff) ^ tw21;
  const uint8_t c2 = ((g_pt2 ^ (g_pt2 >> 8)) & 0xff) ^ tw22;
  const uint8_t bppp1 = ((g_sbox_dec[(g_ct1 >> 8) & 0xff] ^ g_ct1 ^ (g_ct1 >> 16)) & 0xff) ^ tw11;
  const uint8_t appp1 = g_sbox_dec[(g_ct1 >> 16) & 0xff] ^ tw17;
  const uint8_t cppp1 = g_sbox_dec[g_ct1 & 0xff] ^ tw18;
  const uint8_t bppp2 = ((g_sbox_dec[(g_ct2 >> 8) & 0xff] ^ g_ct2 ^ (g_ct2 >> 16)) & 0xff) ^ tw21;
  const uint8_t appp2 = g_sbox_dec[(g_ct2 >> 16) & 0xff] ^ tw27;
  const uint8_t cppp2 = g_sbox_dec[g_ct2 & 0xff] ^ tw28;
  const uint8_t dbpp = bppp1 ^ bppp2;
  const uint8_t dapp = appp1 ^ appp2 ^ dbpp;
  const uint8_t dcpp = cppp1 ^ cppp2 ^ dbpp;
  const uint8_t dacpp = dapp ^ dcpp;
  const uint8_t dtw4 = tw14 ^ tw24;
  const uint8_t dtw5 = tw15 ^ tw25;
  const uint8_t dtw6 = tw16 ^ tw26;

  for (uint16_t k2 = 0; k2 < 256; k2++) {
    const uint8_t bpp1 = bppp1 ^ k2;
    const uint8_t bpp2 = bppp2 ^ k2;
    const uint8_t sbpp1 = g_sbox_dec[bpp1];
    const uint8_t sbpp2 = g_sbox_dec[bpp2];
    const uint8_t dfbpp = sbpp1 ^ sbpp2 ^ dtw6;
    const uint8_t cp1 = g_sbox_enc[c1 ^ k2];
    const uint8_t cp2 = g_sbox_enc[c2 ^ k2];
    const uint8_t dcp = cp1 ^ cp2;
    for (uint16_t k1 = 0; k1 < 256; k1++) {
      const uint8_t ap1 = g_sbox_enc[a1 ^ k1];
      const uint8_t ap2 = g_sbox_enc[a2 ^ k1];
      const uint8_t cpp1 = cppp1 ^ k1 ^ bpp1;
      const uint8_t cpp2 = cppp2 ^ k1 ^ bpp2;
      const uint8_t scpp1 = g_sbox_dec[cpp1];
      const uint8_t scpp2 = g_sbox_dec[cpp2];
      const uint8_t dbp = dcp ^ scpp1 ^ scpp2 ^ dtw5;
      if (dfbpp == (dacpp ^ dbp)) {
        const uint8_t dap = g_sbox_enc[a1 ^ k1] ^ g_sbox_enc[a2 ^ k1] ^ dtw4;
        for (uint16_t k7 = 0; k7 < 256; k7++) {
          const uint8_t app1 = appp1 ^ bpp1 ^ k7;
          const uint8_t app2 = appp2 ^ bpp2 ^ k7;
          const uint8_t sapp1 = g_sbox_dec[app1];
          const uint8_t sapp2 = g_sbox_dec[app2];
          if ((sapp1 ^ sapp2 ^ dap) == dbp) {
            for (uint16_t k3 = 0; k3 < 256; k3++) {
              const uint8_t bp1 = g_sbox_enc[ap1 ^ cp1 ^ b1 ^ k3];
              const uint8_t bp2 = g_sbox_enc[ap2 ^ cp2 ^ b2 ^ k3];
              const uint8_t k41 = sapp1 ^ ap1 ^ bp1 ^ tw14;
              const uint8_t k42 = sapp2 ^ ap2 ^ bp2 ^ tw24;
              const uint8_t k5 = scpp1 ^ cp1 ^ bp1 ^ tw15;
              const uint8_t k6 = sbpp1 ^ app1 ^ cpp1 ^ bp1 ^ tw16;
              if (k41 == k42) {
                uint64_t key = (uint64_t)k1 << 48 | (uint64_t)k2 << 40 | (uint64_t)k3 << 32
                    | (uint64_t)k41 << 24 | (uint64_t)k5 << 16 | (uint64_t)k6 << 8 | k7;
                if (g_pt3 == (uint32_t)-1 || encrypt_lattice(3, g_pt3, key, g_tw3) == g_ct3) {
                  fprintf(g_outfp, "%014" PRIx64 "\n", key);
                  g_keysfound += 1;
                }
              }
            }
          }
        }
      }
    }
  }
  if (g_keysfound == 0) {
    printf("No keys found.\n");
  } else if (g_keysfound == 1) {
    printf("1 key found.\n");
  } else {
    printf("%" PRIu64 " keys found.\n", g_keysfound);
  }
}

void *crack4(void *param) {
  (void)(param); /* Silence unused warning. */
  pthread_mutex_lock(&g_threadcount_lock);
  uint32_t threadid = g_threadcount++;
  pthread_mutex_unlock(&g_threadcount_lock);

  /* Precalculate tweaks. */
  const uint32_t r1tw1 = g_tw1 >> 40;
  const uint32_t r1tw2 = g_tw2 >> 40;
  const uint32_t r4tw1 = (g_tw1 >> 32) & 0xffffff;
  const uint32_t r4tw2 = (g_tw2 >> 32) & 0xffffff;
  const uint8_t tw11 = (g_tw1 >> 56) & 0xff;
  const uint8_t tw14 = (g_tw1 >> 32) & 0xff;
  const uint8_t tw15 = (g_tw1 >> 24) & 0xff;
  const uint8_t tw16 = (g_tw1 >> 16) & 0xff;
  const uint8_t tw17 = (g_tw1 >> 8) & 0xff;
  const uint8_t tw18 = g_tw1 & 0xff;
  const uint8_t tw21 = (g_tw2 >> 56) & 0xff;
  const uint8_t tw24 = (g_tw2 >> 32) & 0xff;
  const uint8_t tw25 = (g_tw2 >> 24) & 0xff;
  const uint8_t tw26 = (g_tw2 >> 16) & 0xff;
  const uint8_t tw27 = (g_tw2 >> 8) & 0xff;
  const uint8_t tw28 = g_tw2 & 0xff;

  struct delta {
    uint8_t k5;
    uint8_t app1;
    uint8_t app2;
    uint8_t bpp1;
    uint8_t bpp2;
    uint8_t cpp1;
    uint8_t cpp2;
    struct delta *next;
    struct delta *last;
  };

  struct delta **lists = (struct delta**)malloc(0x10000 * sizeof(struct delta*));
  struct delta *items = (struct delta*)malloc(0x10000 * sizeof(struct delta));
  if (lists == NULL || items == NULL) {
    fprintf(stderr, "Error: malloc returned null in thread %" PRIu32 ".\n", threadid);
    if (lists != NULL) {
      free(lists);
    }
    if (items != NULL) {
      free(items);
    }
    pthread_mutex_lock(&g_threadcount_lock);
    g_threadcount -= 1;
    pthread_mutex_unlock(&g_threadcount_lock);
    return NULL;
  }

  uint32_t k23;
  while ((k23 = get_next()) < 0x10000) {
    const uint8_t k2 = k23 >> 8;
    const uint8_t k3 = k23 & 0xff;
    memset(lists, 0, 0x10000 * sizeof(struct delta*));
    for (uint32_t k45 = 0; k45 < 0x10000; k45++) {
      const uint8_t k4 = k45 >> 8;
      const uint8_t k5 = k45 & 0xff;
      const uint32_t k345 = ((uint32_t)k3 << 16) | k45;
      const uint32_t r31 = dec_one_round(g_ct1, k345 ^ r4tw1);
      const uint32_t r32 = dec_one_round(g_ct2, k345 ^ r4tw2);
      const uint8_t r31a = (r31 >> 16) & 0xff;
      const uint8_t r31b = (r31 >> 8) & 0xff;
      const uint8_t r31c = r31 & 0xff;
      const uint8_t bpp1 = g_sbox_dec[r31b] ^ r31a ^ r31c ^ k2 ^ tw11;
      const uint8_t r32a = (r32 >> 16) & 0xff;
      const uint8_t r32b = (r32 >> 8) & 0xff;
      const uint8_t r32c = r32 & 0xff;
      const uint8_t bpp2 = g_sbox_dec[r32b] ^ r32a ^ r32c ^ k2 ^ tw21;
      const uint8_t app1 = g_sbox_dec[r31a] ^ bpp1 ^ tw17;
      const uint8_t app2 = g_sbox_dec[r32a] ^ bpp2 ^ tw27;
      const uint8_t cpp1 = g_sbox_dec[r31c] ^ bpp1 ^ tw18;
      const uint8_t cpp2 = g_sbox_dec[r32c] ^ bpp2 ^ tw28;
      const uint16_t addr = k4 * 256 + (app1 ^ app2);
      if (lists[addr] == NULL) {
        lists[addr] = &(items[k45]);
        lists[addr]->k5 = k5;
        lists[addr]->next = NULL;
        lists[addr]->last = lists[addr];
        lists[addr]->app1 = app1;
        lists[addr]->app2 = app2;
        lists[addr]->bpp1 = bpp1;
        lists[addr]->bpp2 = bpp2;
        lists[addr]->cpp1 = cpp1;
        lists[addr]->cpp2 = cpp2;
      } else {
        lists[addr]->last->next = &(items[k45]);
        lists[addr]->last = &(items[k45]);
        lists[addr]->last->k5 = k5;
        lists[addr]->last->next = NULL;
        lists[addr]->last->app1 = app1;
        lists[addr]->last->app2 = app2;
        lists[addr]->last->bpp1 = bpp1;
        lists[addr]->last->bpp2 = bpp2;
        lists[addr]->last->cpp1 = cpp1;
        lists[addr]->last->cpp2 = cpp2;
      }
    }
    for (uint16_t k1 = 0; k1 < 256; k1++) {
      const uint32_t k123 = ((uint32_t)k1 << 16) | ((uint32_t)k2 << 8) | k3;
      const uint32_t r11 = enc_one_round(g_pt1, k123 ^ r1tw1);
      const uint32_t r12 = enc_one_round(g_pt2, k123 ^ r1tw2);
      const uint8_t r11a = r11 >> 16;
      const uint8_t r11b = (r11 >> 8) & 0xff;
      const uint8_t r12a = r12 >> 16;
      const uint8_t r12b = (r12 >> 8) & 0xff;
      for (uint16_t k4 = 0; k4 < 256; k4++) {
        const uint8_t app1 = g_sbox_enc[r11a ^ r11b ^ k4 ^ tw14];
        const uint8_t app2 = g_sbox_enc[r12a ^ r12b ^ k4 ^ tw24];
        struct delta *next = lists[k4 * 256 + (app1 ^ app2)];
        while (next != NULL) {
          const uint8_t r11c = r11 & 0xff;
          const uint8_t r12c = r12 & 0xff;
          const uint8_t cpp1 = g_sbox_enc[r11b ^ r11c ^ next->k5 ^ tw15];
          const uint8_t cpp2 = g_sbox_enc[r12b ^ r12c ^ next->k5 ^ tw25];
          const uint8_t k11 = cpp1 ^ next->cpp1;
          const uint8_t k12 = cpp2 ^ next->cpp2;
          const uint8_t k61 = r11b ^ app1 ^ cpp1 ^ tw16 ^ g_sbox_dec[next->bpp1];
          const uint8_t k62 = r12b ^ app2 ^ cpp2 ^ tw26 ^ g_sbox_dec[next->bpp2];
          const uint8_t k71 = app1 ^ next->app1;
          const uint8_t k72 = app2 ^ next->app2;
          if (k11 == k12 && k61 == k62 && k71 == k72) {
            const uint64_t key = ((uint64_t)k123 << 32) | ((uint64_t)k4) << 24
                | ((uint64_t)(next->k5)) << 16 | ((uint64_t)k61) << 8 | k71;
            if (encrypt_lattice(4, g_pt1, key, g_tw1) == g_ct1
                && encrypt_lattice(4, g_pt2, key, g_tw2) == g_ct2
                && (g_pt3 == (uint32_t)-1 || encrypt_lattice(4, g_pt3, key, g_tw3) == g_ct3)) {
              pthread_mutex_lock(&g_write_lock);
              fprintf(g_outfp, "%014" PRIx64 "\n", key);
              g_keysfound += 1;
              pthread_mutex_unlock(&g_write_lock);
            }
          }
          next = next->next;
        }
      }
    }
  }

  pthread_mutex_lock(&g_threadcount_lock);
  g_threadcount -= 1;
  pthread_mutex_unlock(&g_threadcount_lock);

  return NULL;
}

int main(int argc, char **argv) {
  /* Fill lookup table for the inverse s-box. */
  for (uint16_t i = 0; i < 256; i++) {
    g_sbox_dec[g_sbox_enc[i]] = i;
  }

  assert(enc_one_round(0x54e0cd, 0xc2284a ^ 0x543bd8) == 0xd0721d);
  assert(dec_one_round(0xd0721d, 0xc2284a ^ 0x543bd8) == 0x54e0cd);
  assert(dec_one_round(dec_one_round(0xd0721d, 0xc2284a ^ 0x543bd8), 0) == 0x2ac222);
  assert(encrypt_lattice(3, 0x54e0cd, 0xc2284a1ce7be2f, 0x543bd88000017550) == 0x41db0c);
  assert(encrypt_lattice(4, 0x54e0cd, 0xc2284a1ce7be2f, 0x543bd88000017550) == 0x987c6d);

  const char* usagestr = "Usage:\n"
      "latticecracker rounds outfile plaintext1 ciphertext1 tweak1 plaintext2 ciphertext2 "
      "tweak2 [plaintext3 ciphertext3 tweak3]\n\n";

  if (argc != 9 && argc != 12) {
    printf("%s", usagestr);
    return 1;
  }

  uint32_t nrounds = atoi(argv[1]);
  void *(*crack_func)(void*) = NULL;
  switch (nrounds) {
    case 2:
    case 3:
      /* Handle separately below. */
      break;
    case 4:
      crack_func = crack4;
      break;
    default:
      fprintf(stderr, "Bad number of rounds. Only 2, 3, and 4 rounds are supported.\n");
      return 1;
  }

  g_outfp = fopen(argv[2], "w");
  if (g_outfp == NULL) {
    fprintf(stderr, "Could not open output file for writing.\n");
    return 1;
  }

  g_pt1 = strtoul(argv[3], NULL, 16);
  g_ct1 = strtoul(argv[4], NULL, 16);
  g_tw1 = strtoull(argv[5], NULL, 16);
  g_pt2 = strtoul(argv[6], NULL, 16);
  g_ct2 = strtoul(argv[7], NULL, 16);
  g_tw2 = strtoull(argv[8], NULL, 16);

  printf("PT1: %06" PRIx32 " CT1: %06" PRIx32 " TW1: %016" PRIx64 "\n", g_pt1, g_ct1, g_tw1);
  printf("PT2: %06" PRIx32 " CT2: %06" PRIx32 " TW2: %016" PRIx64 "\n", g_pt2, g_ct2, g_tw2);
  if (argc == 12) {
    g_pt3 = strtoul(argv[9], NULL, 16);
    g_ct3 = strtoul(argv[10], NULL, 16);
    g_tw3 = strtoull(argv[11], NULL, 16);
    printf("PT3: %06" PRIx32 " CT3: %06" PRIx32 " TW3: %016" PRIx64 "\n", g_pt3, g_ct3, g_tw3);
  }

  /* Two or three rounds. */
  if (nrounds == 2 || nrounds == 3) {
    if (nrounds == 2) {
      crack2();
    } else {
      crack3();
    }
    fclose(g_outfp);
    return 0;
  }

  if (pthread_mutex_init(&g_next_lock, NULL) != 0
      || pthread_mutex_init(&g_threadcount_lock, NULL) != 0
      || pthread_mutex_init(&g_write_lock, NULL) != 0) {
    fprintf(stderr, "Mutex init failed.\n");
    fclose(g_outfp);
    return 1;
  }

  /* Create one thread per processor. */
  uint32_t numproc = sysconf(_SC_NPROCESSORS_ONLN);
  pthread_t thread_id[numproc];
  for (uint32_t i = 0; i < numproc; i++) {
    pthread_create(&(thread_id[i]), NULL, crack_func, NULL);
  }

  /* Wait for completion and print progress bar. */
  uint32_t tcount;
  const uint8_t bar[] = "**************************************************";
  const uint8_t nobar[] = "..................................................";
  do {
    usleep(100000);
    pthread_mutex_lock(&g_next_lock);
    uint32_t pct = g_next * 100 / (0xffff - 1);
    pthread_mutex_unlock(&g_next_lock);
    pthread_mutex_lock(&g_write_lock);
    printf("\r[%s%s] %3" PRIu32 "%%  %" PRIu64 " keys found",
        bar + 50 - pct / 2, nobar + pct / 2, pct, g_keysfound);
    fflush(g_outfp);
    pthread_mutex_unlock(&g_write_lock);
    fflush(stdout);

    pthread_mutex_lock(&g_threadcount_lock);
    tcount = g_threadcount;
    pthread_mutex_unlock(&g_threadcount_lock);
  } while (tcount > 0);

  pthread_mutex_destroy(&g_next_lock);
  pthread_mutex_destroy(&g_threadcount_lock);
  pthread_mutex_destroy(&g_write_lock);
  fclose(g_outfp);
  printf("\n");

  return 0;
}
