/* SoCracked

   Attacks up to seven rounds of the Lattice/SoDark algorithm as specified in
   MIL-STD-188-141 and recovers all candidate keys in time proportional to
   2^9 for two rounds, 2^16 for three rounds, 2^33 for four rounds,
   2^49 for five rounds, 2^46 for six rounds, and 2^46 for seven rounds.

   Copyright (C) 2016-2017 Marcus Dansarie <marcus@dansarie.se>

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
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sodark.h"

/* A plaintext-ciphertext-tweak tuple. */
typedef struct {
  uint64_t tw;
  uint32_t pt;
  uint32_t ct;
} tuple_t;

/* A pair of tuples. */
typedef struct {
  tuple_t t1;
  tuple_t t2;
} pair_t;

/* An array of tuple-pairs, with some associated data.
   Used by functions init_pairs, free_pairs, and add_pair. */
typedef struct {
  pair_t *pairs;
  int allocsize;
  int allocstep;
  int num_pairs;
} pairs_t;

pthread_mutex_t g_next_lock;
pthread_mutex_t g_write_lock;
pthread_mutex_t g_threadcount_lock;
uint64_t g_keysfound = 0;           /* Number of keys found so far. */
uint32_t g_threadcount = 0;         /* Number of working threads. */
uint32_t g_next = 0;                /* Next work unit. */
FILE *g_outfp = NULL;               /* Pointer to output file. */
pairs_t g_pairs = {NULL, 0, 0, 0};
tuple_t *g_tuples = NULL;           /* Array of tuples. Used in six- and seven-round attacks. */
int g_num_tuples = 0;               /* Number of tuples in the above array. */
int g_nrounds = 0;                  /* Number of rounds to attack. Used by crack67. */

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

/* Returns the next work unit, i.e. the next value of two key bytes.
   A return value of >= 0x10000 indicates that there are no more work
   units available and that the thread should stop. */

uint32_t get_next() {
  pthread_mutex_lock(&g_next_lock);
  if (g_next >= 0x10000) {
    pthread_mutex_unlock(&g_next_lock);
    return UINT_MAX;
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
          if (g_pt3 == (uint32_t)-1 || encrypt_sodark_3(2, g_pt3, key, g_tw3) == g_ct3) {
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
                if (g_pt3 == (uint32_t)-1 || encrypt_sodark_3(3, g_pt3, key, g_tw3) == g_ct3) {
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
      const uint32_t r31 = dec_one_round_3(g_ct1, k345 ^ r4tw1);
      const uint32_t r32 = dec_one_round_3(g_ct2, k345 ^ r4tw2);
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
      const uint32_t r11 = enc_one_round_3(g_pt1, k123 ^ r1tw1);
      const uint32_t r12 = enc_one_round_3(g_pt2, k123 ^ r1tw2);
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
            if (encrypt_sodark_3(4, g_pt1, key, g_tw1) == g_ct1
                && encrypt_sodark_3(4, g_pt2, key, g_tw2) == g_ct2
                && (g_pt3 == (uint32_t)-1 || encrypt_sodark_3(4, g_pt3, key, g_tw3) == g_ct3)) {
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

void *crack5(void *param) {
  (void)(param); /* Silence unused warning. */
  pthread_mutex_lock(&g_threadcount_lock);
  uint32_t threadid = g_threadcount++;
  pthread_mutex_unlock(&g_threadcount_lock);

  /* Precalculate tweaks. */
  const uint32_t r1tw1 = g_tw1 >> 40;
  const uint32_t r1tw2 = g_tw2 >> 40;
  const uint32_t r2tw1 = (g_tw1 >> 16) & 0xffffff;
  const uint32_t r2tw2 = (g_tw2 >> 16) & 0xffffff;
  const uint32_t r4tw1 = (g_tw1 >> 32) & 0xffffff;
  const uint32_t r4tw2 = (g_tw2 >> 32) & 0xffffff;
  const uint32_t r5tw1 = (g_tw1 >> 8) & 0xffffff;
  const uint32_t r5tw2 = (g_tw2 >> 8) & 0xffffff;

  struct delta {
    uint8_t k2;
    uint32_t delta;
    struct delta *next;
    struct delta *last;
  };

  struct delta items[0x100];
  struct delta *lists[0x100];

  uint32_t k13;
  while ((k13 = get_next()) < 0x10000) {
    const uint8_t k1 = k13 >> 8;
    const uint8_t k3 = k13 & 0xff;
    for (uint32_t k456 = 0x1ce7be; k456 < 0x1000000; k456++) {
      const uint64_t pkey = ((uint64_t)k1 << 48) | ((uint64_t)k3 << 32) | ((uint64_t)k456 << 8);
      uint32_t k345 = ((uint32_t)k3 << 16) | (k456 >> 8);
      memset(lists, 0, 0x100 * sizeof(struct delta*));
      for (uint16_t k2 = 0; k2 < 0x100; k2++) {
        uint32_t k123 = ((uint32_t)k1 << 16) | (k2 << 8) | k3;
        uint32_t v1 = enc_one_round_3(enc_one_round_3(g_pt1, k123 ^ r1tw1), k456 ^ r2tw1);
        uint32_t v2 = enc_one_round_3(enc_one_round_3(g_pt2, k123 ^ r1tw2), k456 ^ r2tw2);
        uint32_t delta = v1 ^ v2;
        uint8_t addr = delta & 0xff;
        if (lists[addr] == NULL) {
          lists[addr] = &(items[k2]);
          lists[addr]->k2 = k2;
          lists[addr]->delta = delta;
          lists[addr]->next = NULL;
          lists[addr]->last = lists[addr];
        } else {
          lists[addr]->last->next = &(items[k2]);
          lists[addr]->last = &(items[k2]);
          lists[addr]->last->k2 = k2;
          lists[addr]->last->delta = delta;
          lists[addr]->last->next = NULL;
        }
      }
      for (uint16_t k7 = 0; k7 < 0x100; k7++) {
        uint32_t k671 = ((k456 & 0xff) << 16) | (k7 << 8) | k1;
        uint32_t v1 = dec_one_round_3(dec_one_round_3(g_ct1, k671 ^ r5tw1), k345 ^ r4tw1);
        uint32_t v2 = dec_one_round_3(dec_one_round_3(g_ct2, k671 ^ r5tw2), k345 ^ r4tw2);
        uint32_t db = g_sbox_dec[(v1 >> 8) & 0xff];
        db ^= g_sbox_dec[(v2 >> 8) & 0xff];
        db ^= v1;
        db ^= v2;
        db ^= v1 >> 16;
        db ^= v2 >> 16;
        db &= 0xff;
        uint32_t da = g_sbox_dec[v1 >> 16];
        da ^= g_sbox_dec[v2 >> 16];
        da ^= db;
        uint32_t dc = g_sbox_dec[v1 & 0xff];
        dc ^= g_sbox_dec[v2 & 0xff];
        dc ^= db;
        uint32_t delta = (da << 16) | (db << 8) | dc;
        uint8_t addr = delta & 0xff;
        struct delta *next = lists[addr];
        while (next != NULL) {
          if (next->delta != delta) {
            next = next->next;
            continue;
          }
          const uint64_t key = pkey | k7 | ((uint64_t)next->k2 << 40);
          if (encrypt_sodark_3(5, g_pt1, key, g_tw1) == g_ct1
              && encrypt_sodark_3(5, g_pt2, key, g_tw2) == g_ct2
              && (g_pt3 == (uint32_t)-1 || encrypt_sodark_3(5, g_pt3, key, g_tw3) == g_ct3)) {
            pthread_mutex_lock(&g_write_lock);
            fprintf(g_outfp, "%014" PRIx64 "\n", key);
            g_keysfound += 1;
            pthread_mutex_unlock(&g_write_lock);
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

void *crack67(void *param) {
  (void)(param); /* Silence unused warning. */
  pthread_mutex_lock(&g_threadcount_lock);
  uint32_t threadid = g_threadcount++;
  pthread_mutex_unlock(&g_threadcount_lock);

  /* Plaintexts. */
  const uint32_t a01 = (g_pt1 >> 16) & 0xff;
  const uint32_t a02 = (g_pt2 >> 16) & 0xff;
  const uint32_t b01 = (g_pt1 >>  8) & 0xff;
  const uint32_t b02 = (g_pt2 >>  8) & 0xff;
  const uint32_t c01 =  g_pt1        & 0xff;
  const uint32_t c02 =  g_pt2        & 0xff;

  /* Tweaks. */
  const uint32_t t11 = (g_tw1 >> 56) & 0xff;
  const uint32_t t12 = (g_tw2 >> 56) & 0xff;
  const uint32_t t21 = (g_tw1 >> 48) & 0xff;
  const uint32_t t22 = (g_tw2 >> 48) & 0xff;
  const uint32_t t31 = (g_tw1 >> 40) & 0xff;
  const uint32_t t32 = (g_tw2 >> 40) & 0xff;
  const uint32_t t41 = (g_tw1 >> 32) & 0xff;
  const uint32_t t42 = (g_tw2 >> 32) & 0xff;
  const uint32_t t51 = (g_tw1 >> 24) & 0xff;
  const uint32_t t52 = (g_tw2 >> 24) & 0xff;
  const uint32_t t61 = (g_tw1 >> 16) & 0xff;
  const uint32_t t62 = (g_tw2 >> 16) & 0xff;
  const uint32_t t71 = (g_tw1 >>  8) & 0xff;
  const uint32_t t72 = (g_tw2 >>  8) & 0xff;
  const uint32_t t81 =  g_tw1        & 0xff;
  const uint32_t t82 =  g_tw2        & 0xff;

  uint32_t k12;
  while ((k12 = get_next()) < 0x10000) {
    int k1 = k12 >> 8;
    int k2 = k12 & 0xff;
    const uint32_t a11 = g_sbox_enc[a01 ^ b01 ^ k1 ^ t11];
    const uint32_t a12 = g_sbox_enc[a02 ^ b02 ^ k1 ^ t12];
    const uint32_t c11 = g_sbox_enc[c01 ^ b01 ^ k2 ^ t21];
    const uint32_t c12 = g_sbox_enc[c02 ^ b02 ^ k2 ^ t22];
    for (int k3 = 0; k3 < 0x100; k3++) {
      const uint32_t b11 = g_sbox_enc[a11 ^ b01 ^ c11 ^ k3 ^ t31];
      const uint32_t b12 = g_sbox_enc[a12 ^ b02 ^ c12 ^ k3 ^ t32];
      for (int k4 = 0; k4 < 0x100; k4++) {
        const uint32_t a21 = g_sbox_enc[a11 ^ b11 ^ k4 ^ t41];
        const uint32_t a22 = g_sbox_enc[a12 ^ b12 ^ k4 ^ t42];
        for (int k5 = 0; k5 < 0x100; k5++) {
          const uint32_t c21 = g_sbox_enc[c11 ^ b11 ^ k5 ^ t51];
          const uint32_t c22 = g_sbox_enc[c12 ^ b12 ^ k5 ^ t52];
          for (int k6 = 0; k6 < 0x100; k6++) {
            const uint32_t b21 = g_sbox_enc[a21 ^ b11 ^ c21 ^ k6 ^ t61];
            const uint32_t b22 = g_sbox_enc[a22 ^ b12 ^ c22 ^ k6 ^ t62];
            const uint32_t c31 = g_sbox_enc[c21 ^ b21 ^ k1 ^ t81];
            const uint32_t c32 = g_sbox_enc[c22 ^ b22 ^ k1 ^ t82];
            if ((c31 ^ c32) == (t51 ^ t52)) {
              uint64_t pkey = ((uint64_t)k1 << 48) | ((uint64_t)k2 << 40) | ((uint64_t)k3 << 32)
                  | ((uint64_t)k4 << 24) | ((uint64_t)k5 << 16) | ((uint64_t)k6 << 8);
              for (int k7 = 0; k7 < 0x100; k7++) {
                uint64_t fullkey = pkey | k7;
                if (encrypt_sodark_3(g_nrounds, g_pt1, fullkey, g_tw1) == g_ct1
                    && encrypt_sodark_3(g_nrounds, g_pt2, fullkey, g_tw2) == g_ct2
                    && (g_pt3 == (uint32_t)-1
                        || encrypt_sodark_3(g_nrounds, g_pt3, fullkey, g_tw3) == g_ct3)) {
                  pthread_mutex_lock(&g_write_lock);
                  fprintf(g_outfp, "%014" PRIx64 "\n", fullkey);
                  g_keysfound += 1;
                  pthread_mutex_unlock(&g_write_lock);
                }
              }
            }
          }
        }
      }
    }
  }

  pthread_mutex_lock(&g_threadcount_lock);
  g_threadcount -= 1;
  pthread_mutex_unlock(&g_threadcount_lock);

  return NULL;
}

static bool init_pairs(pairs_t *pairs) {
  assert(pairs != NULL);
  pairs->allocsize = pairs->allocstep = 100;
  pairs->num_pairs = 0;
  pairs->pairs = malloc(sizeof(pair_t) * pairs->allocsize);
  if (pairs->pairs == NULL) {
    pairs->allocsize = 0;
    fprintf(stderr, "Memory allocation error on line %d.\n", __LINE__);
    return false;
  }
  return true;
}

static void free_pairs(pairs_t *pairs) {
  assert(pairs != NULL);
  free(pairs->pairs);
  pairs->pairs = NULL;
  pairs->allocsize = 0;
  pairs->num_pairs = 0;
}

static bool add_pair(pairs_t *pairs, pair_t p) {
  assert(pairs != NULL);
  assert(pairs->allocsize > 0);
  assert(pairs->allocstep > 0);
  assert(pairs->num_pairs >= 0);
  assert(pairs->num_pairs < pairs->allocsize);
  pairs->pairs[pairs->num_pairs] = p;
  pairs->num_pairs += 1;
  if (pairs->num_pairs == pairs->allocsize) {
    pairs->allocsize += pairs->allocstep;
    pairs->pairs = realloc(pairs->pairs, sizeof(pair_t) * pairs->allocsize);
    if (pairs->pairs == NULL) {
      fprintf(stderr, "Memory allocation error on line %d.\n", __LINE__);
      return false;
    }
  }
  return true;
}

int main(int argc, char **argv) {
  create_sodark_dec_sbox();

  assert(enc_one_round_3(0x54e0cd, 0xc2284a ^ 0x543bd8) == 0xd0721d);
  assert(dec_one_round_3(0xd0721d, 0xc2284a ^ 0x543bd8) == 0x54e0cd);
  assert(dec_one_round_3(dec_one_round_3(0xd0721d, 0xc2284a ^ 0x543bd8), 0) == 0x2ac222);
  assert(encrypt_sodark_3(3, 0x54e0cd, 0xc2284a1ce7be2f, 0x543bd88000017550) == 0x41db0c);
  assert(encrypt_sodark_3(4, 0x54e0cd, 0xc2284a1ce7be2f, 0x543bd88000017550) == 0x987c6d);

  const char* usagestr = "Usage:\n\n"
      "2-5 rounds:\n"
      "%s rounds outfile plaintext1 ciphertext1 tweak1 plaintext2 ciphertext2 "
      "tweak2 [plaintext3 ciphertext3 tweak3]\n\n"
      "6-7 rounds:\n"
      "%s rounds outfile infile\n\n";

  if (argc != 4 && argc != 9 && argc != 12) {
    printf(usagestr, argv[0], argv[0]);
    return 1;
  }

  uint32_t nrounds = atoi(argv[1]);
  if (nrounds < 2 || nrounds > 8) {
    fprintf(stderr, "Bad number of rounds. Only 2 - 8 rounds are supported.\n");
    return 1;
  }

  g_outfp = fopen(argv[2], "w");
  if (g_outfp == NULL) {
    fprintf(stderr, "Could not open output file for writing.\n");
    return 1;
  }

  if (nrounds <= 5) {
    if (argc != 9 && argc != 12) {
      printf(usagestr, argv[0], argv[0]);
      fclose(g_outfp);
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
  } else if (nrounds >= 6 && nrounds <= 7) {
    if (argc != 4 && argc != 12) {
      printf(usagestr, argv[0], argv[0]);
      fclose(g_outfp);
      return 1;
    }
    FILE *infp = fopen(argv[3], "r");
    if (infp == NULL) {
      fprintf(stderr, "Could not open input file for reading.\n");
      fclose(g_outfp);
      return 1;
    }
    printf("Reading input file... ");
    fflush(stdout);

    const int allocstep = 1000;
    int allocsize = allocstep;
    g_tuples = malloc(sizeof(tuple_t) * allocstep);
    if (g_tuples == NULL) {
      fprintf(stderr, "Memory allocation error on line %d.\n", __LINE__);
      fclose(g_outfp);
      fclose(infp);
      return 1;
    }

    while (!feof(infp)) {
      if (fscanf(infp, "%06x %06x %016" PRIx64 "\n", &g_tuples[g_num_tuples].pt,
          &g_tuples[g_num_tuples].ct, &g_tuples[g_num_tuples].tw) == 3) {
        g_num_tuples += 1;
        if (g_num_tuples == allocsize) {
          allocsize += allocstep;
          g_tuples = realloc(g_tuples, sizeof(tuple_t) * allocsize);
          if (g_tuples == NULL) {
            fprintf(stderr, "Memory allocation error.\n");
            fclose(g_outfp);
            fclose(infp);
            return 1;
          }
        }
      } else {
        int c;
        while ((c = fgetc(infp)) != '\n' && c != EOF) {
          /* Empty. */
        }
      }
    }
    fclose(infp);
    infp = NULL;
    printf("%d tuples loaded.\n", g_num_tuples);
    printf("Filtering pairs... ");
    fflush(stdout);

    if (!init_pairs(&g_pairs)) {
      free(g_tuples);
      fclose(g_outfp);
      return 1;
    }

    for (int i = 0; i < g_num_tuples; i++) {
      for (int k = i + 1; k < g_num_tuples; k++) {
        uint64_t delta_tw = g_tuples[i].tw ^ g_tuples[k].tw;
        if (delta_tw & 0xffffffff00ffffffL
            || ((delta_tw >> 24) & 0xff) == 0) {
          continue;
        }
        if (nrounds == 6) {
          if (g_tuples[i].ct == g_tuples[k].ct) {
            pair_t p = {g_tuples[i], g_tuples[k]};
            if (!add_pair(&g_pairs, p)) {
              free(g_tuples);
              fclose(g_outfp);
              return 1;
            }
          }
        } else if (nrounds == 7) {
          if (((g_tuples[i].ct ^ g_tuples[k].ct) & 0xff00ff) == 0) {
            uint8_t a1 =  g_tuples[i].ct >> 16;
            uint8_t a2 =  g_tuples[k].ct >> 16;
            uint8_t b1 = (g_tuples[i].ct >> 8) & 0xff;
            uint8_t b2 = (g_tuples[k].ct >> 8) & 0xff;
            uint8_t c1 =  g_tuples[i].ct & 0xff;
            uint8_t c2 =  g_tuples[k].ct & 0xff;
            uint8_t t1 = (g_tuples[i].tw >> 24) & 0xff;
            uint8_t t2 = (g_tuples[k].tw >> 24) & 0xff;
            uint8_t dbh = g_sbox_dec[b1] ^ a1 ^ c1 ^ t1 ^ g_sbox_dec[b2] ^ a2 ^ c2 ^ t2;
            if (dbh == 0) {
              pair_t p = {g_tuples[i], g_tuples[k]};
              if (!add_pair(&g_pairs, p)) {
                free(g_tuples);
                fclose(g_outfp);
                return 1;
              }
            }
          }
        } else {
          assert(0);
        }
      }
    }
    printf("%d potential pairs found.\n", g_pairs.num_pairs);
    if (g_pairs.num_pairs == 0) {
      free(g_tuples);
      fclose(g_outfp);
      return 0;
    }
    printf("Only one pair needed. Using first pair.\n");
    g_pt1 = g_pairs.pairs[0].t1.pt;
    g_pt2 = g_pairs.pairs[0].t2.pt;
    g_ct1 = g_pairs.pairs[0].t1.ct;
    g_ct2 = g_pairs.pairs[0].t2.ct;
    g_tw1 = g_pairs.pairs[0].t1.tw;
    g_tw2 = g_pairs.pairs[0].t2.tw;

    for (int i = 0; i < g_num_tuples; i++) {
      if (!((g_tuples[i].pt == g_pt1 && g_tuples[i].ct == g_ct1 && g_tuples[i].tw == g_tw1)
          || (g_tuples[i].pt == g_pt2 && g_tuples[i].ct == g_ct2 && g_tuples[i].tw == g_tw2))) {
        g_pt3 = g_tuples[i].pt;
        g_ct3 = g_tuples[i].ct;
        g_tw3 = g_tuples[i].tw;
        break;
      }
    }

    printf("Tuple 1: %06x %06x %016" PRIx64 "\n", g_pt1, g_ct1, g_tw1);
    printf("Tuple 2: %06x %06x %016" PRIx64 "\n", g_pt2, g_ct2, g_tw2);
    if (g_pt3 != (uint32_t)-1) {
      printf("Tuple 3: %06x %06x %016" PRIx64 "\n", g_pt3, g_ct3, g_tw3);
    }
  } /* nrounds >= 6 && nrounds <= 7 */

  void *(*crack_func)(void*) = NULL;
  switch (nrounds) {
    case 2:
      crack2();
      fclose(g_outfp);
      return 0;
    case 3:
      crack3();
      fclose(g_outfp);
      return 0;
    case 4:
      crack_func = crack4;
      break;
    case 5:
      crack_func = crack5;
      break;
    case 6:
    case 7:
      crack_func = crack67;
      g_nrounds = nrounds;
      break;
    default:
      fprintf(stderr, "Error: %d\n", nrounds);
      assert(0);
  }

  if (pthread_mutex_init(&g_next_lock, NULL) != 0
      || pthread_mutex_init(&g_threadcount_lock, NULL) != 0
      || pthread_mutex_init(&g_write_lock, NULL) != 0) {
    fprintf(stderr, "Mutex init failed.\n");
    fclose(g_outfp);
    free(g_tuples);
    if (g_pairs.pairs != NULL) {
      free_pairs(&g_pairs);
    }
    return 1;
  }

  /* Create one thread per processor. */
  uint32_t numproc = sysconf(_SC_NPROCESSORS_ONLN);
  pthread_t thread_id[numproc];
  for (uint32_t i = 0; i < numproc; i++) {
    if (pthread_create(&(thread_id[i]), NULL, crack_func, NULL) != 0) {
      fprintf(stderr, "Error returned from pthread_create. i=%d. numproc=%d\n", i, numproc);
      fclose(g_outfp);
      free(g_tuples);
      if (g_pairs.pairs != NULL) {
        free_pairs(&g_pairs);
      }
      return 1;
    }
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
  free(g_tuples);
  if (g_pairs.pairs != NULL) {
    free_pairs(&g_pairs);
  }
  printf("\n");

  return 0;
}
