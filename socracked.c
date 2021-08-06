/* SoCracked

   Attacks up to eight rounds of the Lattice/SoDark algorithm as specified in
   MIL-STD-188-141 and recovers all candidate keys in time proportional to
   2^9 for two rounds, 2^16 for three rounds, 2^33 for four rounds,
   2^49 for five rounds, 2^46 for six rounds, 2^46 for seven rounds, and
   2^45 for eight rounds. Attacks on more than six rounds require certain
   properties of the plaintext-ciphertext-tuple tweaks. In particular, this
   means that successful attacks require a couple of thousand tuples that
   differ in tweak byte five only. The program also performs known-plaintext
   brute force attacks on up to sixteen rounds of the cipher.

   Copyright (C) 2016-2018, 2020 Marcus Dansarie <marcus@dansarie.se>

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

#define _GNU_SOURCE
#include <assert.h>
#include <curses.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "sodark.h"
#include "socracked.h"

#ifdef WITH_CUDA
#include "socracked_cuda.h"
const bool CUDA_ENABLED = true;
#else
const bool CUDA_ENABLED = false;
#endif

pthread_mutex_t g_next_lock;
pthread_mutex_t g_write_lock;
pthread_mutex_t g_threadcount_lock;
bool g_prof = false;
bool g_mutexes_initialized = false;
bool g_exit = false;                      /* Indicates that the worker threads should shut down. */
uint32_t g_num_cpu_threads;               /* Number of worker threads. */
uint32_t g_num_threads;
int g_num_cuda_devices = 0;               /* Number of CUDA devices. */
uint32_t g_cuda_count = 0;                /* Indicates which CUDA device to use. */
double *g_thread_speeds;                  /* Individual thread cracking speeds in calls to get_next
                                             per second. */
struct timeval *g_last_get_next_calls;    /* Used for calculation of thread speeds. */
uint64_t g_keysfound = 0;                 /* Number of keys found so far. */
uint64_t g_last_key_found = (uint64_t)-1; /* Last key found. */
uint32_t g_threadcount = 0;               /* Number of working threads. */
uint32_t g_next = 0;                      /* Next work unit. */
uint32_t g_next_pair = 0;                 /* Next pair. (Used when cracking 6, 7, and 8 rounds. */
pairs_t  g_pairs = {NULL, 0, 0, 0};       /* Candidate pairs. Holds pairs for get_next_678. */
FILE *g_outfp = NULL;                     /* Pointer to output file. */

#define STATUS_BUF_LEN (51)
char g_status[STATUS_BUF_LEN] = "";
pair_t g_current_pair = {{0, 0, 0}, {0, 0, 0}, {0}, 0};

/* Updates the current cracking speed in the g_thread_speeds array. Called
   whenever a thread fetches a new work unit. */
static void update_thread_speed(uint32_t threadid) {
  struct timeval time_now;
  gettimeofday(&time_now, NULL);
  if (g_last_get_next_calls[threadid].tv_sec > 0) {
    double elapsed = time_now.tv_sec - g_last_get_next_calls[threadid].tv_sec
        + (time_now.tv_usec - g_last_get_next_calls[threadid].tv_usec) / 1E6;
    g_thread_speeds[threadid] = 1.0 / elapsed;
  }
  g_last_get_next_calls[threadid] = time_now;
}

/* Gets the status line in the user interface. */
void set_status(const char *status) {
  pthread_mutex_lock(&g_write_lock);
  memset(g_status, ' ', STATUS_BUF_LEN - 1);
  for (int i = 0; i < strlen(status) && i < STATUS_BUF_LEN - 1; i++) {
    g_status[i] = status[i];
  }
  g_status[STATUS_BUF_LEN - 1] = '\0';
  pthread_mutex_unlock(&g_write_lock);
}

/* Returns the current user interface status line. */
static void get_status(char *status) {
  pthread_mutex_lock(&g_write_lock);
  strncpy(status, g_status, STATUS_BUF_LEN);
  status[STATUS_BUF_LEN - 1] = '\0';
  pthread_mutex_unlock(&g_write_lock);
}

/* Returns the next work unit, i.e. the next value of two key bytes.
   Returns false to indicate that there are no more work units available and
   that the thread should stop. */
static bool get_next(uint32_t threadid, uint32_t *next) {
  update_thread_speed(threadid);
  pthread_mutex_lock(&g_next_lock);
  if (g_next >= 0x10000) {
    set_status("Done. Waiting for threads.");
    pthread_mutex_unlock(&g_next_lock);
    return false;
  }
  *next = g_next;
  g_next += 1;
  pthread_mutex_unlock(&g_next_lock);
  return true;
}

/* Returns the next work unit when cracking 6, 7, or 8 rounds. Returns false to indicate that there
   are no more work units available and that the thread should stop. */
bool get_next_678(uint32_t threadid, uint32_t *k12, pair_t **pair) {
  update_thread_speed(threadid);
  pthread_mutex_lock(&g_next_lock);
  if (g_next_pair >= g_pairs.num_pairs) {
    set_status("Done. Waiting for threads.");
    pthread_mutex_unlock(&g_next_lock);
    return false;
  }
  *k12 = g_next;
  *pair = &g_pairs.pairs[g_next_pair];
  g_next += 1;
  if (!g_prof && g_next == 0x10000) {
    g_next = 0;
    g_next_pair += 1;
  }
  if (g_prof && g_next > 0xc228) {
    g_next_pair = g_pairs.num_pairs;
  }
  g_current_pair = **pair;
  pthread_mutex_unlock(&g_next_lock);
  return true;
}

/* Tests a candidate key against all known tuples. Returns true if the key is
   a match for all of them. */
bool test_key(uint32_t rounds, uint64_t key, tuple_t *tuples, uint32_t num_tuples) {
  for (uint32_t i = 0; i < num_tuples; i++) {
    if (encrypt_sodark_3(rounds, tuples[i].pt, key, tuples[i].tw) != tuples[i].ct) {
      return false;
    }
  }
  return true;
}

/* Called by a cracking thread to write a found key to file and to update the
   number of keys found.*/
void found_key(uint64_t key) {
  pthread_mutex_lock(&g_write_lock);
  fprintf(g_outfp, "%014" PRIx64 "\n", key);
  fflush(g_outfp);
  g_keysfound += 1;
  g_last_key_found = key;
  pthread_mutex_unlock(&g_write_lock);
}

/* Returns the number of keys found so far. */
static uint64_t get_keys_found() {
  pthread_mutex_lock(&g_write_lock);
  uint64_t keysfound = g_keysfound;
  pthread_mutex_unlock(&g_write_lock);
  return keysfound;
}

/* Returns the last key found. */
static uint64_t get_last_key_found() {
  pthread_mutex_lock(&g_write_lock);
  uint64_t last_key = g_last_key_found;
  pthread_mutex_unlock(&g_write_lock);
  return last_key;
}

/* Cracks two rounds. */
void crack2(tuple_t *tuples, uint32_t num_tuples) {
  assert(num_tuples > 1);
  const uint8_t tw11 = (tuples[0].tw >> 56) & 0xff;
  const uint8_t tw12 = (tuples[0].tw >> 48) & 0xff;
  const uint8_t tw13 = (tuples[0].tw >> 40) & 0xff;
  const uint8_t tw14 = (tuples[0].tw >> 32) & 0xff;
  const uint8_t tw15 = (tuples[0].tw >> 24) & 0xff;
  const uint8_t tw16 = (tuples[0].tw >> 16) & 0xff;
  const uint8_t tw21 = (tuples[1].tw >> 56) & 0xff;
  const uint8_t tw22 = (tuples[1].tw >> 48) & 0xff;
  const uint8_t tw23 = (tuples[1].tw >> 40) & 0xff;
  const uint8_t tw24 = (tuples[1].tw >> 32) & 0xff;
  const uint8_t tw25 = (tuples[1].tw >> 24) & 0xff;
  const uint8_t tw26 = (tuples[1].tw >> 16) & 0xff;
  const uint8_t b1 = ((tuples[0].pt >> 8) & 0xff) ^ tw13;
  const uint8_t a1 = (((tuples[0].pt >> 16) ^ (tuples[0].pt >> 8)) & 0xff) ^ tw11;
  const uint8_t c1 = ((tuples[0].pt ^ (tuples[0].pt >> 8)) & 0xff) ^ tw12;
  const uint8_t b2 = ((tuples[1].pt >> 8) & 0xff) ^ tw23;
  const uint8_t a2 = (((tuples[1].pt >> 16) ^ (tuples[1].pt >> 8)) & 0xff) ^ tw21;
  const uint8_t c2 = ((tuples[1].pt ^ (tuples[1].pt >> 8)) & 0xff) ^ tw22;
  const uint8_t app1 = (tuples[0].ct >> 16) & 0xff;
  const uint8_t app2 = (tuples[1].ct >> 16) & 0xff;
  const uint8_t cpp1 = tuples[0].ct & 0xff;
  const uint8_t cpp2 = tuples[1].ct & 0xff;
  const uint8_t bpp1 = g_sbox_dec[(tuples[0].ct >> 8) & 0xff] ^ app1 ^ cpp1 ^ tw16;
  const uint8_t bpp2 = g_sbox_dec[(tuples[1].ct >> 8) & 0xff] ^ app2 ^ cpp2 ^ tw26;
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
          if (test_key(2, key, tuples, num_tuples)) {
            found_key(key);
          }
        }
      }
    }
  }
  uint64_t keysfound = get_keys_found();
  if (keysfound == 0) {
    printf("No keys found.\n");
  } else if (keysfound == 1) {
    printf("1 key found.\n");
  } else {
    printf("%" PRIu64 " keys found.\n", keysfound);
  }
}

/* Cracks three rounds. */
void crack3(tuple_t *tuples, uint32_t num_tuples) {
  assert(num_tuples > 1);
  const uint8_t tw11 = (tuples[0].tw >> 56) & 0xff;
  const uint8_t tw12 = (tuples[0].tw >> 48) & 0xff;
  const uint8_t tw13 = (tuples[0].tw >> 40) & 0xff;
  const uint8_t tw14 = (tuples[0].tw >> 32) & 0xff;
  const uint8_t tw15 = (tuples[0].tw >> 24) & 0xff;
  const uint8_t tw16 = (tuples[0].tw >> 16) & 0xff;
  const uint8_t tw17 = (tuples[0].tw >> 8) & 0xff;
  const uint8_t tw18 = tuples[0].tw & 0xff;
  const uint8_t tw21 = (tuples[1].tw >> 56) & 0xff;
  const uint8_t tw22 = (tuples[1].tw >> 48) & 0xff;
  const uint8_t tw23 = (tuples[1].tw >> 40) & 0xff;
  const uint8_t tw24 = (tuples[1].tw >> 32) & 0xff;
  const uint8_t tw25 = (tuples[1].tw >> 24) & 0xff;
  const uint8_t tw26 = (tuples[1].tw >> 16) & 0xff;
  const uint8_t tw27 = (tuples[1].tw >> 8) & 0xff;
  const uint8_t tw28 = tuples[1].tw & 0xff;
  const uint8_t b1 = ((tuples[0].pt >> 8) & 0xff) ^ tw13;
  const uint8_t a1 = (((tuples[0].pt >> 16) ^ (tuples[0].pt >> 8)) & 0xff) ^ tw11;
  const uint8_t c1 = ((tuples[0].pt ^ (tuples[0].pt >> 8)) & 0xff) ^ tw12;
  const uint8_t b2 = ((tuples[1].pt >> 8) & 0xff) ^ tw23;
  const uint8_t a2 = (((tuples[1].pt >> 16) ^ (tuples[1].pt >> 8)) & 0xff) ^ tw21;
  const uint8_t c2 = ((tuples[1].pt ^ (tuples[1].pt >> 8)) & 0xff) ^ tw22;
  const uint8_t bppp1 = ((g_sbox_dec[(tuples[0].ct >> 8) & 0xff] ^ tuples[0].ct
      ^ (tuples[0].ct >> 16)) & 0xff) ^ tw11;
  const uint8_t appp1 = g_sbox_dec[(tuples[0].ct >> 16) & 0xff] ^ tw17;
  const uint8_t cppp1 = g_sbox_dec[tuples[0].ct & 0xff] ^ tw18;
  const uint8_t bppp2 = ((g_sbox_dec[(tuples[1].ct >> 8) & 0xff] ^ tuples[1].ct
      ^ (tuples[1].ct >> 16)) & 0xff) ^ tw21;
  const uint8_t appp2 = g_sbox_dec[(tuples[1].ct >> 16) & 0xff] ^ tw27;
  const uint8_t cppp2 = g_sbox_dec[tuples[1].ct & 0xff] ^ tw28;
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
                if (test_key(3, key, tuples, num_tuples)) {
                  found_key(key);
                }
              }
            }
          }
        }
      }
    }
  }
  uint64_t keysfound = get_keys_found();
  if (keysfound == 0) {
    printf("No keys found.\n");
  } else if (keysfound == 1) {
    printf("1 key found.\n");
  } else {
    printf("%" PRIu64 " keys found.\n", keysfound);
  }
}

/* Cracking thread function for 4 rounds. */
void *crack4(void *p) {
  worker_param_t params = *((worker_param_t*)p);
  tuple_t *tuples = params.tuples;
  uint32_t num_tuples = params.num_tuples;
  assert(num_tuples > 1);
  assert(params.nrounds == 4);

  pthread_mutex_lock(&g_threadcount_lock);
  uint32_t threadid = g_threadcount++;
  pthread_mutex_unlock(&g_threadcount_lock);

  struct delta **lists = NULL;
  struct delta *items = NULL;

  if (g_exit) {
    goto exit4;
  }

  /* Precalculate tweaks. */
  const uint32_t r1tw1 = tuples[0].tw >> 40;
  const uint32_t r1tw2 = tuples[1].tw >> 40;
  const uint32_t r4tw1 = (tuples[0].tw >> 32) & 0xffffff;
  const uint32_t r4tw2 = (tuples[1].tw >> 32) & 0xffffff;
  const uint8_t tw11 = (tuples[0].tw >> 56) & 0xff;
  const uint8_t tw14 = (tuples[0].tw >> 32) & 0xff;
  const uint8_t tw15 = (tuples[0].tw >> 24) & 0xff;
  const uint8_t tw16 = (tuples[0].tw >> 16) & 0xff;
  const uint8_t tw17 = (tuples[0].tw >> 8) & 0xff;
  const uint8_t tw18 = tuples[0].tw & 0xff;
  const uint8_t tw21 = (tuples[1].tw >> 56) & 0xff;
  const uint8_t tw24 = (tuples[1].tw >> 32) & 0xff;
  const uint8_t tw25 = (tuples[1].tw >> 24) & 0xff;
  const uint8_t tw26 = (tuples[1].tw >> 16) & 0xff;
  const uint8_t tw27 = (tuples[1].tw >> 8) & 0xff;
  const uint8_t tw28 = tuples[1].tw & 0xff;

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

  lists = (struct delta**)malloc(0x10000 * sizeof(struct delta*));
  items = (struct delta*)malloc(0x10000 * sizeof(struct delta));
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
  while (get_next(threadid, &k23)) {
    if (g_exit) {
      goto exit4;
    }
    const uint8_t k2 = k23 >> 8;
    const uint8_t k3 = k23 & 0xff;
    memset(lists, 0, 0x10000 * sizeof(struct delta*));
    for (uint32_t k45 = 0; k45 < 0x10000; k45++) {
      const uint8_t k4 = k45 >> 8;
      const uint8_t k5 = k45 & 0xff;
      const uint32_t k345 = ((uint32_t)k3 << 16) | k45;
      const uint32_t r31 = dec_one_round_3(tuples[0].ct, k345 ^ r4tw1);
      const uint32_t r32 = dec_one_round_3(tuples[1].ct, k345 ^ r4tw2);
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
      const uint32_t r11 = enc_one_round_3(tuples[0].pt, k123 ^ r1tw1);
      const uint32_t r12 = enc_one_round_3(tuples[1].pt, k123 ^ r1tw2);
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
            if (test_key(4, key, tuples, num_tuples)) {
              found_key(key);
            }
          }
          next = next->next;
        }
      }
    }
  }

exit4:
  free(lists);
  free(items);
  pthread_mutex_lock(&g_threadcount_lock);
  g_threadcount -= 1;
  pthread_mutex_unlock(&g_threadcount_lock);

  return NULL;
}

/* Cracking thread function for 5 rounds. */
void *crack5(void *p) {
  worker_param_t params = *((worker_param_t*)p);
  tuple_t *tuples = params.tuples;
  uint32_t num_tuples = params.num_tuples;
  assert(num_tuples > 1);
  assert(params.nrounds == 5);

  pthread_mutex_lock(&g_threadcount_lock);
  uint32_t threadid = g_threadcount++;
  pthread_mutex_unlock(&g_threadcount_lock);

  if (g_exit) {
    goto exit5;
  }

  /* Precalculate tweaks. */
  const uint32_t r1tw1 = tuples[0].tw >> 40;
  const uint32_t r1tw2 = tuples[1].tw >> 40;
  const uint32_t r2tw1 = (tuples[0].tw >> 16) & 0xffffff;
  const uint32_t r2tw2 = (tuples[1].tw >> 16) & 0xffffff;
  const uint32_t r4tw1 = (tuples[0].tw >> 32) & 0xffffff;
  const uint32_t r4tw2 = (tuples[1].tw >> 32) & 0xffffff;
  const uint32_t r5tw1 = (tuples[0].tw >> 8) & 0xffffff;
  const uint32_t r5tw2 = (tuples[1].tw >> 8) & 0xffffff;

  struct delta {
    uint8_t k2;
    uint32_t delta;
    struct delta *next;
    struct delta *last;
  };

  struct delta items[0x100];
  struct delta *lists[0x100];

  uint32_t k13;
  while (get_next(threadid, &k13)) {
    if (g_prof && k13 != 0xc24a) {
      goto exit5;
    }
    const uint8_t k1 = k13 >> 8;
    const uint8_t k3 = k13 & 0xff;
    for (uint32_t k456 = 0; k456 < 0x1000000; k456++) {
      const uint64_t pkey = ((uint64_t)k1 << 48) | ((uint64_t)k3 << 32) | ((uint64_t)k456 << 8);
      uint32_t k345 = ((uint32_t)k3 << 16) | (k456 >> 8);
      memset(lists, 0, 0x100 * sizeof(struct delta*));
      for (uint16_t k2 = 0; k2 < 0x100; k2++) {
        uint32_t k123 = ((uint32_t)k1 << 16) | (k2 << 8) | k3;
        uint32_t v1 = enc_one_round_3(enc_one_round_3(tuples[0].pt, k123 ^ r1tw1), k456 ^ r2tw1);
        uint32_t v2 = enc_one_round_3(enc_one_round_3(tuples[1].pt, k123 ^ r1tw2), k456 ^ r2tw2);
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
        if (g_exit) {
          goto exit5;
        }
        uint32_t k671 = ((k456 & 0xff) << 16) | (k7 << 8) | k1;
        uint32_t v1 = dec_one_round_3(dec_one_round_3(tuples[0].ct, k671 ^ r5tw1), k345 ^ r4tw1);
        uint32_t v2 = dec_one_round_3(dec_one_round_3(tuples[1].ct, k671 ^ r5tw2), k345 ^ r4tw2);
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
          if (test_key(5, key, tuples, num_tuples)) {
            found_key(key);
          }
          next = next->next;
        }
      }
    }
  }

exit5:
  pthread_mutex_lock(&g_threadcount_lock);
  g_threadcount -= 1;
  pthread_mutex_unlock(&g_threadcount_lock);

  return NULL;
}

/* Cracking thread function for 6, 7, and 8 rounds. */
void *crack678(void *p) {
  worker_param_t params = *((worker_param_t*)p);
  assert(params.num_tuples > 1);
  assert(params.nrounds > 5 && params.nrounds < 9);

  pthread_mutex_lock(&g_threadcount_lock);
  uint32_t threadid = g_threadcount++;
  pthread_mutex_unlock(&g_threadcount_lock);

  if (g_exit) {
    pthread_mutex_lock(&g_threadcount_lock);
    g_threadcount -= 1;
    pthread_mutex_unlock(&g_threadcount_lock);
    return NULL;
  }

  uint32_t k12;
  pair_t *pair;
  while (get_next_678(threadid, &k12, &pair)) {
    int k1 = k12 >> 8;
    int k2 = k12 & 0xff;

    /* Plaintexts. */
    const uint32_t a01 = (pair->t1.pt >> 16) & 0xff;
    const uint32_t a02 = (pair->t2.pt >> 16) & 0xff;
    const uint32_t b01 = (pair->t1.pt >>  8) & 0xff;
    const uint32_t b02 = (pair->t2.pt >>  8) & 0xff;
    const uint32_t c01 =  pair->t1.pt        & 0xff;
    const uint32_t c02 =  pair->t2.pt        & 0xff;

    /* Tweaks. */
    const uint32_t t11 = (pair->t1.tw >> 56) & 0xff;
    const uint32_t t12 = (pair->t2.tw >> 56) & 0xff;
    const uint32_t t21 = (pair->t1.tw >> 48) & 0xff;
    const uint32_t t22 = (pair->t2.tw >> 48) & 0xff;
    const uint32_t t31 = (pair->t1.tw >> 40) & 0xff;
    const uint32_t t32 = (pair->t2.tw >> 40) & 0xff;
    const uint32_t t41 = (pair->t1.tw >> 32) & 0xff;
    const uint32_t t42 = (pair->t2.tw >> 32) & 0xff;
    const uint32_t t51 = (pair->t1.tw >> 24) & 0xff;
    const uint32_t t52 = (pair->t2.tw >> 24) & 0xff;
    const uint32_t t61 = (pair->t1.tw >> 16) & 0xff;
    const uint32_t t62 = (pair->t2.tw >> 16) & 0xff;
    const uint32_t t81 =  pair->t1.tw        & 0xff;
    const uint32_t t82 =  pair->t2.tw        & 0xff;

    const uint32_t a11 = g_sbox_enc[a01 ^ b01 ^ k1 ^ t11];
    const uint32_t a12 = g_sbox_enc[a02 ^ b02 ^ k1 ^ t12];
    const uint32_t c11 = g_sbox_enc[c01 ^ b01 ^ k2 ^ t21];
    const uint32_t c12 = g_sbox_enc[c02 ^ b02 ^ k2 ^ t22];
    for (int k3p = 0; k3p < pair->num_k3; k3p++) {
      int k3 = pair->k3[k3p];
      const uint32_t b11 = g_sbox_enc[a11 ^ b01 ^ c11 ^ k3 ^ t31];
      const uint32_t b12 = g_sbox_enc[a12 ^ b02 ^ c12 ^ k3 ^ t32];
      for (int k4 = 0; k4 < 0x100; k4++) {
        if (g_exit) {
          goto exit678;
        }
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
                if (test_key(params.nrounds, fullkey, params.tuples, params.num_tuples)) {
                  found_key(fullkey);
                }
              }
            }
          }
        }
      }
    }
  }

exit678:
  pthread_mutex_lock(&g_threadcount_lock);
  g_threadcount -= 1;
  pthread_mutex_unlock(&g_threadcount_lock);

  return NULL;
}

#ifdef WITH_CUDA
void *cuda_crack(void *p, bool brute) {
  worker_param_t params = *((worker_param_t*)p);
  assert(params.num_tuples > 1);
  assert(params.nrounds > 5 && params.nrounds <= 16);

  pthread_mutex_lock(&g_threadcount_lock);
  uint32_t threadid = g_threadcount++;
  uint32_t cuda_device = g_cuda_count++ % g_num_cuda_devices;
  pthread_mutex_unlock(&g_threadcount_lock);

  if (g_exit) {
    pthread_mutex_lock(&g_threadcount_lock);
    g_threadcount -= 1;
    pthread_mutex_unlock(&g_threadcount_lock);
    return NULL;
  }

  if (brute) {
    cuda_brute(params, threadid, cuda_device, params.nrounds);
  } else {
    cuda_fast(params, threadid, cuda_device);
  }

  pthread_mutex_lock(&g_threadcount_lock);
  g_threadcount -= 1;
  pthread_mutex_unlock(&g_threadcount_lock);

  return NULL;
}

void *cuda_crack_brute(void *p) {
  return cuda_crack(p, true);
}

void *cuda_crack_fast(void *p) {
  return cuda_crack(p, false);
}
#endif /* WITH_CUDA */

/* Initializes a list of tuple-pairs. */
static bool init_pairs(pairs_t *pairs) {
  assert(pairs != NULL);
  pairs->allocsize = pairs->allocstep = 100;
  pairs->num_pairs = 0;
  pairs->pairs = malloc(sizeof(pair_t) * pairs->allocsize);
  if (pairs->pairs == NULL) {
    pairs->allocsize = 0;
    endwin();
    fprintf(stderr, "Memory allocation error on line %d.\n", __LINE__);
    return false;
  }
  return true;
}

/* Frees a list of tuple-pairs. */
static void free_pairs(pairs_t *pairs) {
  assert(pairs != NULL);
  free(pairs->pairs);
  pairs->pairs = NULL;
  pairs->allocsize = 0;
  pairs->num_pairs = 0;
}

/* Adds a pair to a list of tuple-pairs. Returns true on success and false on failure. */
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
      endwin();
      fprintf(stderr, "Memory allocation error on line %d.\n", __LINE__);
      return false;
    }
  }
  return true;
}

bool init_tuples(worker_param_t *worker_params) {
  worker_params->allocstep = 1000;
  worker_params->allocsize = worker_params->allocstep;
  worker_params->num_tuples = 0;
  worker_params->tuples = malloc(sizeof(tuple_t) * worker_params->allocsize);
  if (worker_params->tuples == NULL) {
    endwin();
    fprintf(stderr, "Memory allocation error on line %d.\n", __LINE__);
    return true;
  }
  return false;
}

void free_tuples(worker_param_t *worker_params) {
  free(worker_params->tuples);
  worker_params->tuples = NULL;
  worker_params->allocsize = 0;
  worker_params->num_tuples = 0;
}

bool add_tuple(worker_param_t *worker_params, tuple_t tuple) {
  worker_params->tuples[worker_params->num_tuples].pt = tuple.pt;
  worker_params->tuples[worker_params->num_tuples].ct = tuple.ct;
  worker_params->tuples[worker_params->num_tuples].tw = tuple.tw;
  worker_params->num_tuples += 1;
  if (worker_params->num_tuples == worker_params->allocsize) {
    worker_params->allocsize += worker_params->allocstep;
    worker_params->tuples = realloc(worker_params->tuples,
        sizeof(tuple_t) * worker_params->allocsize);
    if (worker_params->tuples == NULL) {
      endwin();
      fprintf(stderr, "Memory allocation error on line %d.\n", __LINE__);
      return true;
    }
  }
  return false;
}

void get_elapsed_time(struct timeval start_time, struct timeval time_now,
    int *days, int *hours, int *minutes, int *seconds) {
  int elapsed = time_now.tv_sec - start_time.tv_sec;
  *days = elapsed / 86400;
  elapsed -= *days * 86400;
  *hours = elapsed / 3600;
  elapsed -= *hours * 3600;
  *minutes = elapsed / 60;
  elapsed -= *minutes * 60;
  *seconds = elapsed;
}

#define PRINT_BACKGROUND_STRING(y, x, maxy, str) \
  if (y < (maxy - 2)) {\
    mvprintw(y, x, str);\
  } else {\
    refresh();\
    return;\
  }

/* Draws the static background to the screen. */
static void draw_background(WINDOW *screen) {
  assert(screen != NULL);
  int maxx = 0;
  int maxy = 0;
  (void)maxx; /* Silence unused warning. */
  getmaxyx(screen, maxy, maxx);
  clear();
  bkgd(COLOR_PAIR(1));
  border(0, 0, 0, 0, 0, 0, 0, 0);
  attrset(COLOR_PAIR(1));
  if (CUDA_ENABLED) {
    PRINT_BACKGROUND_STRING(1,  1,  maxy, "SoCracked v. " SOCRACKED_VERSION " (CUDA)");
  } else {
    PRINT_BACKGROUND_STRING(1,  1,  maxy, "SoCracked v. " SOCRACKED_VERSION);
  }
  PRINT_BACKGROUND_STRING(3,  1,  maxy, "Start time:");
  PRINT_BACKGROUND_STRING(4,  1,  maxy, "Elapsed time:");
  PRINT_BACKGROUND_STRING(5,  1,  maxy, "Estimated finish:");
  PRINT_BACKGROUND_STRING(6,  1,  maxy, "Success probability:");
  PRINT_BACKGROUND_STRING(8,  1,  maxy, "Rounds:");
  PRINT_BACKGROUND_STRING(9,  1,  maxy, "Tuple 1:");
  PRINT_BACKGROUND_STRING(10, 1,  maxy, "Tuple 2:");
  PRINT_BACKGROUND_STRING(11, 1,  maxy, "Keys found:");
  PRINT_BACKGROUND_STRING(12, 1,  maxy, "Last key found:");
  PRINT_BACKGROUND_STRING(14, 1,  maxy, "Pairs:");
  PRINT_BACKGROUND_STRING(14, 22, maxy, "[");
  PRINT_BACKGROUND_STRING(14, 77, maxy, "]");
  PRINT_BACKGROUND_STRING(15, 1,  maxy, "Keys:");
  PRINT_BACKGROUND_STRING(15, 22, maxy, "[");
  PRINT_BACKGROUND_STRING(15, 77, maxy, "]");
  PRINT_BACKGROUND_STRING(17, 1,  maxy, "Status:");
  PRINT_BACKGROUND_STRING(18, 1,  maxy, "CPU threads:");
  if (CUDA_ENABLED) {
    PRINT_BACKGROUND_STRING(19, 1,  maxy, "CUDA devices:");
  }
  refresh();
}

#define RETURN_IF_MAXY(maxy, y) if (y > (maxy - 3)) { refresh(); return; }

/* Draws all dynamic content on the screen.
   start_time  UTC time that the program was started.
   psuccess    Calculated probability of success, as a percentage (0.0 <= p <= 100.0).
               Values outside this range result in no probability being printed.
   rounds      Number of rounds cracked.
   screen      Window reference.
   qonce       True if Q has already been pressed once. */
static void draw_foreground(struct timeval start_time, double psuccess, uint32_t rounds,
    WINDOW *screen, bool qonce) {
  assert(screen != NULL);
  attrset(COLOR_PAIR(1));
  int maxx = 0;
  int maxy = 0;
  (void)maxx; /* Silence unused warning. */
  getmaxyx(screen, maxy, maxx);
  if (qonce) {
    mvprintw(maxy - 2, 1, "Press Q to quit.      ");
  } else {
    mvprintw(maxy - 2, 1, "Press Q twice to quit.");
  }

  RETURN_IF_MAXY(maxy, 3);

  attrset(COLOR_PAIR(2));

  /* Start time */
  struct tm *stime = gmtime(&start_time.tv_sec);
  mvprintw(3,  22, "%04d-%02d-%02d %02d:%02d:%02d UTC", 1900 + stime->tm_year, stime->tm_mon + 1,
      stime->tm_mday, stime->tm_hour, stime->tm_min, stime->tm_sec);
  RETURN_IF_MAXY(maxy, 4);

  /* Elapsed time */
  struct timeval time_now;
  gettimeofday(&time_now, NULL);
  int days, hours, minutes, seconds;
  get_elapsed_time(start_time, time_now, &days, &hours, &minutes, &seconds);
  mvprintw(4,  22, "%dd %02d:%02d:%02d", days, hours, minutes, seconds);
  RETURN_IF_MAXY(maxy, 5);

  /* Finish time */
  if (g_thread_speeds != NULL) {
    double tspeed = 0.0;
    bool all_valid = true;
    time_t speed_update_time = 0;
    for (int i = 0; i < g_num_threads; i++) {
      if (g_thread_speeds[i] <= 0.0) {
        all_valid = false;
        break;
      }
      tspeed += g_thread_speeds[i];
      if (g_last_get_next_calls[i].tv_sec > speed_update_time) {
        speed_update_time = g_last_get_next_calls[i].tv_sec;
      }
    }
    if (all_valid) {
      time_t finish_time = speed_update_time + (0x10000 - g_next) / tspeed;
      if (rounds > 5) {
        pthread_mutex_lock(&g_next_lock);
        finish_time += (0x10000 * (g_pairs.num_pairs - g_next_pair - 1)) / tspeed;
        pthread_mutex_unlock(&g_next_lock);
      }
      stime = gmtime(&finish_time);
      if (stime != NULL) {
        mvprintw(5,  22, "%04d-%02d-%02d %02d:%02d:%02d UTC", 1900 + stime->tm_year,
            stime->tm_mon + 1, stime->tm_mday, stime->tm_hour, stime->tm_min, stime->tm_sec);
      }
    }
  }
  RETURN_IF_MAXY(maxy, 6);

  if (psuccess >= 0.0 && psuccess <= 100.0) {
    mvprintw(6, 22, "%.1f%%", psuccess);
  }
  RETURN_IF_MAXY(maxy, 8);

  mvprintw(8,  22, "%d    ", rounds);
  RETURN_IF_MAXY(maxy, 9);
  pthread_mutex_lock(&g_next_lock);
  mvprintw(9,  22, "%06" PRIx32 " %06" PRIx32 " %016" PRIx64,
      g_current_pair.t1.pt, g_current_pair.t1.ct, g_current_pair.t1.tw); /* Tuple 1 */
  if (10 > (maxy - 3)) {
    pthread_mutex_unlock(&g_next_lock);
    refresh();
    return;
  }
  mvprintw(10, 22, "%06" PRIx32 " %06" PRIx32 " %016" PRIx64,
      g_current_pair.t2.pt, g_current_pair.t2.ct, g_current_pair.t2.tw); /* Tuple 2 */
  pthread_mutex_unlock(&g_next_lock);
  RETURN_IF_MAXY(maxy, 11);
  mvprintw(11, 22, "%d", get_keys_found());
  if (maxy < 12) {
    refresh();
    return;
  }
  uint64_t last_key = get_last_key_found();
  if (last_key < 0x100000000000000) {
    mvprintw(12, 22, "%014" PRIx64, get_last_key_found());
  }
  RETURN_IF_MAXY(maxy, 14);

  const char bar[] = "                                                      ";
  pthread_mutex_lock(&g_next_lock);
  uint32_t num_pairs = rounds > 5 ? g_pairs.num_pairs : 1;
  uint32_t current_pair = rounds > 5 ? g_next_pair : 0;
  mvprintw(14, 8,  "%d of %-6d", current_pair + 1 > num_pairs ? num_pairs : current_pair + 1,
      num_pairs);
  int bars = 0;
  if (num_pairs > 0) {
    bars = strlen(bar) * current_pair / num_pairs;
  }
  mvprintw(14, 23, "%s", bar);
  attrset(COLOR_PAIR(3));
  mvprintw(14, 23, "%s", bar + strlen(bar) - bars);
  attrset(COLOR_PAIR(2));
  pthread_mutex_unlock(&g_next_lock);
  RETURN_IF_MAXY(maxy, 15);

  pthread_mutex_lock(&g_next_lock);
  double pct = g_next * 100.0 / (0xffff - 1);
  double pct_per_bar = 100.0 / strlen(bar);
  bars = (int)(pct / pct_per_bar);
  pthread_mutex_unlock(&g_next_lock);
  mvprintw(15, 8,  "%.1f%%   ", pct); /* Key percentage. */
  mvprintw(15, 23, "%s", bar);
  attrset(COLOR_PAIR(3));
  mvprintw(15, 23, "%s", bar + strlen(bar) - bars);
  attrset(COLOR_PAIR(2));
  RETURN_IF_MAXY(maxy, 17);

  char status[STATUS_BUF_LEN];
  get_status(status);
  mvprintw(17, 22, "%s", status);
  mvprintw(18, 22, "%d", g_num_cpu_threads);
  if (CUDA_ENABLED) {
    mvprintw(19, 22, "%d", g_num_cuda_devices);
  }
  refresh();
}

void cleanup_globals() {
  if (g_outfp != NULL) {
    fclose(g_outfp);
    g_outfp = NULL;
  }
  if (g_pairs.pairs != NULL) {
    free_pairs(&g_pairs);
  }
  free(g_thread_speeds);
  free(g_last_get_next_calls);
  g_thread_speeds = NULL;
  g_last_get_next_calls = NULL;
  if (g_mutexes_initialized) {
    pthread_mutex_destroy(&g_next_lock);
    pthread_mutex_destroy(&g_write_lock);
    pthread_mutex_destroy(&g_threadcount_lock);
    g_mutexes_initialized = false;
  }
}

bool start_threads(void *(*crack_func)(void*), void *(*cuda_crack_func)(void*),
    worker_param_t *worker_params) {

  if (g_prof && worker_params->nrounds == 5) {
    g_next = 0xc24a;
  } else if (g_prof && worker_params->nrounds > 5) {
    g_next = 0xc228;
  } else {
    g_next = 0;
  }
  g_next_pair = 0;
  memset(g_thread_speeds, 0, sizeof(double) * g_num_threads);
  memset(g_last_get_next_calls, 0, sizeof(struct timeval) * g_num_threads);
  /* Ensure the started threads wait until all threads have been created. */
  pthread_mutex_lock(&g_threadcount_lock);

  pthread_t thread_id[g_num_cpu_threads];
  pthread_t cuda_thread_id[g_num_cuda_devices];
  memset(thread_id, 0, sizeof(pthread_t) * g_num_cpu_threads);
  memset(cuda_thread_id, 0, sizeof(pthread_t) * g_num_cuda_devices);
  cpu_set_t cpus;
  pthread_attr_t attr;
  pthread_attr_init(&attr);

  /* Start CPU threads. */
  if (crack_func != NULL) {

    for (uint32_t i = 0; i < g_num_cpu_threads; i++) {
      CPU_ZERO(&cpus);
      CPU_SET(i, &cpus);
      pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
      if (pthread_create(&(thread_id[i]), &attr, crack_func, worker_params) != 0) {
        g_exit = true;
        pthread_mutex_unlock(&g_threadcount_lock);
        endwin();
        fprintf(stderr, "Error returned from pthread_create. i=%d. g_num_cpu_threads=%d. "
            "line=%d.\n", i, g_num_cpu_threads, __LINE__);
        for (int k = 0; k < i; k++) {
          pthread_join(thread_id[k], NULL);
        }
      }
    }
  }

  if (cuda_crack_func != NULL) {
    uint32_t num_processors = sysconf(_SC_NPROCESSORS_ONLN);
    for (uint32_t i = 0; i < g_num_cuda_devices; i++) {
      CPU_ZERO(&cpus);
      CPU_SET((i % num_processors), &cpus);
      pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
      if (pthread_create(&(cuda_thread_id[i]), &attr, cuda_crack_func, worker_params) != 0) {
        g_exit = true;
        pthread_mutex_unlock(&g_threadcount_lock);
        endwin();
        fprintf(stderr, "Error returned from pthread_create. i=%d. g_num_cpu_threads=%d. "
            "line=%d.\n", i, g_num_cpu_threads, __LINE__);
        for (int k = 0; k < g_num_cpu_threads; k++) {
          pthread_join(thread_id[k], NULL);
        }
        for (int k = 0; k < i; k++) {
          pthread_join(cuda_thread_id[k], NULL);
        }
        return false;
      }
    }
  }

  pthread_attr_destroy(&attr);
  pthread_mutex_unlock(&g_threadcount_lock);
  return true;
}

bool run_progress_screen(WINDOW *screen, struct timeval start_time, double psuccess,
    uint32_t nrounds) {

  uint32_t tcount;
  uint32_t qcount = 0;
  bool userquit = false;
  do {
    if (qcount > 0) {
      qcount--;
    }
    draw_foreground(start_time, psuccess, nrounds, screen, qcount > 0);
    usleep(100000);

    pthread_mutex_lock(&g_threadcount_lock);
    tcount = g_threadcount;
    pthread_mutex_unlock(&g_threadcount_lock);
    int keypress;
    do {
      keypress = getch();
      if (keypress == KEY_RESIZE) {
        draw_background(screen);
      } else if (keypress == 'q' || keypress == 'Q') {
        if (qcount > 0) {
          g_exit = true;
          set_status("Exiting.");
          userquit = true;
        } else {
          qcount = 20;
        }
      }
    } while (keypress != ERR);
  } while (tcount > 0);

  return userquit;
}

bool read_input_tuples(worker_param_t *worker_params, FILE *infp) {
  /* Read tuples from input file. */
  while (!feof(infp)) {
    tuple_t tuple;
    if (fscanf(infp, "%06x %06x %016" PRIx64 "\n", &tuple.pt, &tuple.ct, &tuple.tw) == 3) {
      if (add_tuple(worker_params, tuple)) {
        return true;
      }
    } else {
      int c;
      while ((c = fgetc(infp)) != '\n' && c != EOF) {
        /* Empty. */
      }
    }
  }

  /* Ensure first two pairs are unique. */
  while (worker_params->num_tuples > 1
      && worker_params->tuples[0].pt == worker_params->tuples[1].pt
      && worker_params->tuples[0].ct == worker_params->tuples[1].ct
      && worker_params->tuples[0].tw == worker_params->tuples[1].tw) {
    for (int i = 2; i < worker_params->num_tuples; i++) {
      worker_params->tuples[i - 1] = worker_params->tuples[i];
    }
    worker_params->num_tuples -= 1;
  }
  g_current_pair.t1 = worker_params->tuples[0];
  g_current_pair.t2 = worker_params->tuples[1];

  if (worker_params->num_tuples < 2) {
    endwin();
    fprintf(stderr, "At least two valid tuples are required.\n");
    return 1;
  }

  return false;
}

int main(int argc, char **argv) {
  create_sodark_dec_sbox();

  /* Sanity tests. */
  assert(enc_one_round_3(0x54e0cd, 0xc2284a ^ 0x543bd8) == 0xd0721d);
  assert(dec_one_round_3(0xd0721d, 0xc2284a ^ 0x543bd8) == 0x54e0cd);
  assert(dec_one_round_3(dec_one_round_3(0xd0721d, 0xc2284a ^ 0x543bd8), 0) == 0x2ac222);
  assert(encrypt_sodark_3(3, 0x54e0cd, 0xc2284a1ce7be2f, 0x543bd88000017550) == 0x41db0c);
  assert(encrypt_sodark_3(4, 0x54e0cd, 0xc2284a1ce7be2f, 0x543bd88000017550) == 0x987c6d);

  #ifdef WITH_CUDA
  if (argc == 2 && strcmp(argv[1], "-devices") == 0) {
    list_cuda_devices();
    return 0;
  }
  #endif /* WITH_CUDA */

  /* Check if correct number of arguments. */
  if (argc != 4 && argc != 5) {
    fprintf(stderr, "Usage: %s rounds/-c infile outfile\n\n", argv[0]);
    return 1;
  } else if (argc == 5) {
    if (strcmp(argv[4], "-prof") == 0) {
      g_prof = true;
    } else {
      fprintf(stderr, "Usage: %s rounds/-c infile outfile\n\n", argv[0]);
      return 1;
    }
  }

  worker_param_t worker_params;
  memset(&worker_params, 0, sizeof(worker_param_t));

  /* Check if the number of rounds is supported. */
  if (strcmp(argv[1], "-c") == 0) {
    worker_params.nrounds = CHOSEN_CIPHERTEXT;
  } else {
    worker_params.nrounds = atoi(argv[1]);
    int max_rounds = 8;
    if (CUDA_ENABLED) {
      max_rounds = 16;
    }
    if (worker_params.nrounds < 2 || worker_params.nrounds > max_rounds) {
      fprintf(stderr, "Bad number of rounds. Only 2 - %d rounds are supported.\n", max_rounds);
      return 1;
    }
  }

  /* Open input file. */
  FILE *infp = fopen(argv[2], "r");
  if (infp == NULL) {
    fprintf(stderr, "Could not open input file for reading.\n");
    return 1;
  }

  /* Open output file. */
  g_outfp = fopen(argv[3], "w");
  if (g_outfp == NULL) {
    fprintf(stderr, "Could not open output file for writing.\n");
    fclose(infp);
    return 1;
  }

  /* Record start time. */
  struct timeval start_time;
  gettimeofday(&start_time, NULL);

  /* Draw a screen if cracking more than 3 rounds. Three rounds and fewer are cracked so fast that
     drawing anything to the screen is unnecessary. */
  double psuccess = -1.0;
  WINDOW *screen = NULL;
  if (worker_params.nrounds > 3) {
    screen = initscr();
    if (screen == NULL) {
      fprintf(stderr, "Error when initializing curses.\n");
      fclose(infp);
      cleanup_globals();
      return 1;
    }
    cbreak();
    noecho();
    nodelay(stdscr, TRUE);
    if (has_colors()) {
      start_color();
      init_pair(1, COLOR_WHITE, COLOR_BLUE);
      init_pair(2, COLOR_GREEN, COLOR_BLUE);
      init_pair(3, COLOR_GREEN, COLOR_GREEN);
    }
    curs_set(0);
    set_status("Reading input file. ");
    draw_background(screen);
    draw_foreground(start_time, psuccess, worker_params.nrounds, screen, false);
  }

  if (init_tuples(&worker_params)) {
    return true;
  }

  if (worker_params.nrounds != CHOSEN_CIPHERTEXT) {
    if (read_input_tuples(&worker_params, infp)) {
      free_tuples(&worker_params);
      fclose(infp);
      cleanup_globals();
      return 1;
    }
  }

  if (!init_pairs(&g_pairs)) {
    /* init_pairs has printed an error message. */
    free_tuples(&worker_params);
    fclose(infp);
    cleanup_globals();
    return 1;
  }

  if (worker_params.nrounds == CHOSEN_CIPHERTEXT) {
    while (!feof(infp)) {
      pair_t pair = {0};
      if (fscanf(infp, "%06x %06x %016" PRIx64 " %06x %06x %016" PRIx64 " %02x\n", &pair.t1.pt,
          &pair.t1.ct, &pair.t1.tw, &pair.t2.pt, &pair.t2.ct, &pair.t2.tw, pair.k3) == 7) {
        pair.num_k3 = 1;
        add_tuple(&worker_params, pair.t1);
        add_tuple(&worker_params, pair.t2);
        add_pair(&g_pairs, pair);
      } else {
        int c;
        while ((c = fgetc(infp)) != '\n' && c != EOF) {
          /* Empty. */
        }
      }
    }
  }

  fclose(infp);
  infp = NULL;

  /* Perform filtering step when cracking 5-8 rounds. */
  if (worker_params.nrounds > 5 && worker_params.nrounds <= 8) {
    set_status("Filtering pairs. ");
    draw_foreground(start_time, psuccess, worker_params.nrounds, screen, false);

    pair_t pair;
    for (uint16_t i = 0; i < 0x100; i++) {
      pair.k3[i] = i;
    }
    pair.num_k3 = 0x100;

    /* Generate all possible pairs. */
    for (int i = 0; i < worker_params.num_tuples; i++) {
      for (int k = i + 1; k < worker_params.num_tuples; k++) {
        /* Eliminate pairs that don't have the necessary tweak difference. */
        uint64_t delta_tw = worker_params.tuples[i].tw ^ worker_params.tuples[k].tw;
        if (delta_tw & 0xffffffff00ffffffL || ((delta_tw >> 24) & 0xff) == 0) {
          continue;
        }

        uint8_t a1 =  worker_params.tuples[i].ct >> 16;
        uint8_t a2 =  worker_params.tuples[k].ct >> 16;
        uint8_t b1 = (worker_params.tuples[i].ct >> 8) & 0xff;
        uint8_t b2 = (worker_params.tuples[k].ct >> 8) & 0xff;
        uint8_t c1 =  worker_params.tuples[i].ct & 0xff;
        uint8_t c2 =  worker_params.tuples[k].ct & 0xff;

        if (worker_params.nrounds == 6) {
          if (worker_params.tuples[i].ct == worker_params.tuples[k].ct) {
            pair.t1 = worker_params.tuples[i];
            pair.t2 = worker_params.tuples[k];
            if (!add_pair(&g_pairs, pair)) {
              /* add_pair has printed an error message. */
              free_tuples(&worker_params);
              cleanup_globals();
              return 1;
            }
          }
        } else if (worker_params.nrounds == 7) {
          if (((worker_params.tuples[i].ct ^ worker_params.tuples[k].ct) & 0xff00ff) == 0) {
            uint8_t t1 = (worker_params.tuples[i].tw >> 24) & 0xff;
            uint8_t t2 = (worker_params.tuples[k].tw >> 24) & 0xff;
            uint8_t dbh = g_sbox_dec[b1] ^ a1 ^ c1 ^ t1 ^ g_sbox_dec[b2] ^ a2 ^ c2 ^ t2;
            if (dbh == 0) {
              pair.t1 = worker_params.tuples[i];
              pair.t2 = worker_params.tuples[k];
              if (!add_pair(&g_pairs, pair)) {
                /* add_pair has printed an error message. */
                free_tuples(&worker_params);
                cleanup_globals();
                return 1;
              }
            }
          }
        } else if (worker_params.nrounds == 8) {
          if ((g_sbox_dec[a1] ^ g_sbox_dec[a2]) == (g_sbox_dec[c1] ^ g_sbox_dec[c2])
              && (g_sbox_dec[a1] ^ g_sbox_dec[a2])
                  == (g_sbox_dec[b1] ^ g_sbox_dec[b2] ^ a1 ^ a2 ^ c1 ^ c2)) {
            uint8_t t51 = (worker_params.tuples[i].tw >> 24) & 0xff;
            uint8_t t52 = (worker_params.tuples[k].tw >> 24) & 0xff;
            uint8_t t81 =  worker_params.tuples[i].tw & 0xff;
            uint8_t t82 =  worker_params.tuples[k].tw & 0xff;
            pair.t1 = worker_params.tuples[i];
            pair.t2 = worker_params.tuples[k];
            pair.num_k3 = 0;
            for (uint32_t k3 = 0; k3 < 0x100; k3++) {
              if ((g_sbox_dec[g_sbox_dec[b1] ^ a1 ^ c1 ^ k3 ^ t81]
                  ^ g_sbox_dec[g_sbox_dec[b2] ^ a2 ^ c2 ^ k3 ^ t82]) == (t51 ^ t52)) {
                pair.k3[pair.num_k3++] = k3;
              }
            }
            if (pair.num_k3 == 0) {
              continue;
            }
            if (!add_pair(&g_pairs, pair)) {
              /* add_pair has printed an error message. */
              free_tuples(&worker_params);
              cleanup_globals();
              return 1;
            }
          }
        } else {
          assert(0);
        }
      }
    }
  } /* worker_params.nrounds > 5 && worker_params.nrounds <= 8 */

  psuccess = 100.0;

  if (worker_params.nrounds == CHOSEN_CIPHERTEXT) {
    worker_params.nrounds = 8;
  }

  /* Select cracking function. */
  void *(*crack_func)(void*) = NULL;
  void *(*cuda_crack_func)(void*) = NULL;
  switch (worker_params.nrounds) {
    case 2:
      crack2(worker_params.tuples, worker_params.num_tuples);
      free_tuples(&worker_params);
      cleanup_globals();
      return 0;
    case 3:
      crack3(worker_params.tuples, worker_params.num_tuples);
      free_tuples(&worker_params);
      cleanup_globals();
      return 0;
    case 4:
      crack_func = crack4;
      break;
    case 5:
      crack_func = crack5;
      break;
    case 6:
    case 7:
      if (g_pairs.num_pairs == 0) {
        if (CUDA_ENABLED) {
          pair_t pa;
          for (uint16_t i = 0; i < 0x100; i++) {
            pa.k3[i] = i;
          }
          pa.num_k3 = 0x100;
          pa.t1 = worker_params.tuples[0];
          pa.t2 = worker_params.tuples[1];
          add_pair(&g_pairs, pa);
          crack_func = NULL;
          #ifdef WITH_CUDA
          cuda_crack_func = cuda_crack_brute;
          #endif /* WITH_CUDA */
        } else {
          endwin();
          free_tuples(&worker_params);
          cleanup_globals();
          printf("No candidate pairs found.\n");
          return 0;
        }
      } else {
        g_pairs.num_pairs = 1;
        crack_func = crack678;
        #ifdef WITH_CUDA
        cuda_crack_func = cuda_crack_fast;
        #endif /* WITH_CUDA */
      }
      break;
    case 8:
      if (g_pairs.num_pairs == 0) {
        if (CUDA_ENABLED) {
          pair_t pa;
          for (uint16_t i = 0; i < 0x100; i++) {
            pa.k3[i] = i;
          }
          pa.num_k3 = 0x100;
          pa.t1 = worker_params.tuples[0];
          pa.t2 = worker_params.tuples[1];
          add_pair(&g_pairs, pa);
          crack_func = NULL;
          #ifdef WITH_CUDA
          cuda_crack_func = cuda_crack_brute;
          #endif /* WITH_CUDA */
        } else {
          endwin();
          free_tuples(&worker_params);
          cleanup_globals();
          printf("No candidate pairs found.\n");
          return 0;
        }
      } else {
        psuccess = 100.0 * (1.0 - pow(0.989795918, g_pairs.num_pairs));
        crack_func = crack678;
        #ifdef WITH_CUDA
        cuda_crack_func = cuda_crack_fast;
        #endif /* WITH_CUDA */
      }
      break;
    default:
      /* More than eight rounds: brute force only. */
      if (CUDA_ENABLED) {
        psuccess = 100.0;
        pair_t pa;
        for (uint16_t i = 0; i < 0x100; i++) {
          pa.k3[i] = i;
        }
        pa.num_k3 = 0x100;
        pa.t1 = worker_params.tuples[0];
        pa.t2 = worker_params.tuples[1];
        add_pair(&g_pairs, pa);
        crack_func = NULL;
        #ifdef WITH_CUDA
        cuda_crack_func = cuda_crack_brute;
        #endif /* WITH_CUDA */
      } else {
        fprintf(stderr, "Error: %d\n", worker_params.nrounds);
        assert(0);
      }
  }

  /* Initialize mutexes. */
  if (pthread_mutex_init(&g_next_lock, NULL) != 0
      || pthread_mutex_init(&g_threadcount_lock, NULL) != 0
      || pthread_mutex_init(&g_write_lock, NULL) != 0) {
    endwin();
    cleanup_globals();
    fprintf(stderr, "Mutex init failed.\n");
    return 1;
  }
  g_mutexes_initialized = true;

  if (CUDA_ENABLED) {
    #ifdef WITH_CUDA
    g_num_cuda_devices = get_num_cuda_devices();
    #endif /* WITH_CUDA */
    if (g_num_cuda_devices <= 0 && worker_params.nrounds > 8) {
      endwin();
      const char *errstr = "No CUDA devices found.";
      if (g_num_cuda_devices < 0) {
        errstr = "Error when getting number of CUDA devices.";
      }
      fprintf(stderr, "%s CPU brute force cracking not supported.\n", errstr);
      free_tuples(&worker_params);
      cleanup_globals();
      return 1;
    }
    if (g_prof) {
        g_num_cuda_devices = g_num_cuda_devices > 0 ? 1 : 0;
    }
  } else {
    g_num_cuda_devices = 0;
  }
  g_num_cpu_threads = sysconf(_SC_NPROCESSORS_ONLN);

  if (CUDA_ENABLED && worker_params.nrounds > 5 && g_num_cuda_devices > 0) {
    /* Use CUDA. */
    g_num_cpu_threads = 0;
    g_num_threads = g_num_cuda_devices;
  } else {
    /* Use CPU threads. */
    g_num_cuda_devices = 0;
    g_num_threads = g_num_cpu_threads;
  }

  g_thread_speeds = malloc(sizeof(double) * g_num_threads);
  g_last_get_next_calls = malloc(sizeof(struct timeval) * g_num_threads);
  if (g_thread_speeds == NULL || g_last_get_next_calls == NULL) {
    endwin();
    fprintf(stderr, "Malloc failed on line %d.\n", __LINE__);
    free_tuples(&worker_params);
    cleanup_globals();
    return 1;
  }

  if (start_threads(crack_func, cuda_crack_func, &worker_params) != true) {
    free_tuples(&worker_params);
    cleanup_globals();
    return 1;
  }

  /* Wait for completion and keep screen updated. */
  #ifdef WITH_CUDA
  if (cuda_crack_func == cuda_crack_brute) {
    set_status("Performing brute force key search.");
  } else {
    set_status("Performing key search.");
  }
  #else /* WITH_CUDA */
  set_status("Performing key search.");
  #endif /* WITH_CUDA */

  bool userquit = run_progress_screen(screen, start_time, psuccess, worker_params.nrounds);

  #ifdef WITH_CUDA
  if (!userquit && worker_params.nrounds == 8 && get_keys_found() == 0
      && cuda_crack_func != cuda_crack_brute && g_num_cuda_devices > 0) {
    set_status("Performing brute force key search.");
    g_pairs.num_pairs = 1;

    if (start_threads(NULL, cuda_crack_brute, &worker_params) != true) {
      free_tuples(&worker_params);
      cleanup_globals();
      return 1;
    }
    run_progress_screen(screen, start_time, 100.0, worker_params.nrounds);
  }
  #else
  (void)userquit; /* Silence unused warning. */
  #endif /* WITH_CUDA */

  endwin();
  uint64_t keysfound = get_keys_found();
  struct timeval time_now;
  gettimeofday(&time_now, NULL);
  int days, hours, minutes, seconds;
  get_elapsed_time(start_time, time_now, &days, &hours, &minutes, &seconds);
  char timestr[50];
  snprintf(timestr, 50, "%dd %02d:%02d:%02d", days, hours, minutes, seconds);
  timestr[49] = '\0';
  if (keysfound == 0) {
    printf("No keys found in %s.\n", timestr);
  } else if (keysfound == 1) {
    printf("1 key found in %s.\n", timestr);
  } else {
    printf("%" PRIu64 " keys found in %s.\n", keysfound, timestr);
  }
  free_tuples(&worker_params);
  cleanup_globals();

  return 0;
}
