/* latticecracker
   Performs a meet-in-the-middle attack on three or four rounds of the Lattice algorithm as
   specified in MIL-STD-188-141 and recovers all candidate keys in 2^33 time for three rounds of
   encryption and 2^40 time for four rounds of encryption.
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
uint32_t g_threadcount = 0; /* Number of working threads. */
uint32_t g_next = 0;        /* Next work unit. (Value of key bytes 1 and 2.) */
FILE *g_outfp = NULL;       /* Pointer to output file. */

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
void *crack3(void *param);
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

void *crack3(void *param) {
  (void)(param); /* Silence unused warning. */
  pthread_mutex_lock(&g_threadcount_lock);
  uint32_t threadid = g_threadcount++;
  pthread_mutex_unlock(&g_threadcount_lock);

  /* Precalculate round tweaks. */
  uint32_t r1tw = (g_tw1 >> 40);
  uint32_t r2tw = (g_tw1 >> 16) & 0xffffff;
  r2tw = (r2tw & 0xff0000) | ((r2tw & 0xff) << 8) | ((r2tw & 0xff00) >> 8);
  r2tw = r2tw ^ ((r2tw & 0xff00) << 8) ^ ((r2tw & 0xff00) >> 8);
  uint32_t r3tw = ((g_tw1 >> 56) | (g_tw1 << 8)) & 0xffffff;

  uint64_t *kkeys = (uint64_t*)malloc(0x10000 * sizeof(uint64_t));
  if (kkeys == NULL) {
    fprintf(stderr, "Error: malloc returned null in thread %" PRIu32 ".\n", threadid);
    pthread_mutex_lock(&g_threadcount_lock);
    g_threadcount -= 1;
    pthread_mutex_unlock(&g_threadcount_lock);
    return NULL;
  }

  uint32_t outer;
  while ((outer = get_next()) < 0x10000) { /* Key bytes 1 and 2. */
    uint32_t forward[256];
    for (uint16_t k3 = 0; k3 < 256; k3++) {
      uint32_t rkey = ((outer << 8) | k3) ^ r1tw;
      forward[k3] = enc_one_round(g_pt1, rkey);
    }
    /* Calculate 65536 candidate keys. */
    for (uint16_t k7 = 0; k7 < 256; k7++) {
      uint32_t rkey = (outer | (k7 << 16)) ^ r3tw;
      uint32_t back = dec_one_round(dec_one_round(g_ct1, rkey), 0);
      for (uint16_t k3 = 0; k3 < 256; k3++) {
        uint32_t k456 = forward[k3] ^ back ^ r2tw;
        k456 = k456 ^ ((k456 & 0xff00) << 8) ^ ((k456 & 0xff00) >> 8);
        k456 = (k456 & 0xff0000) | ((k456 & 0xff) << 8) | ((k456 & 0xff00) >> 8);
        kkeys[k7 * 256 + k3] = ((uint64_t)outer << 40) | ((uint64_t)k3 << 32)
            | ((uint64_t)k456 << 8) | k7;
      }
    }

    /* Do trial encryptions with the candidate keys and write the successful ones to file. */
    for (uint32_t i = 0; i < 0x10000; i++) {
      if (encrypt_lattice(3, g_pt2, kkeys[i], g_tw2) == g_ct2) {
        if (g_pt3 == (uint32_t)-1 || encrypt_lattice(3, g_pt3, kkeys[i], g_tw3) == g_ct3) {
          pthread_mutex_lock(&g_write_lock);
          fprintf(g_outfp, "%014" PRIx64 "\n", kkeys[i]);
          g_keysfound += 1;
          pthread_mutex_unlock(&g_write_lock);
        }
      }
    }
  }

  pthread_mutex_lock(&g_threadcount_lock);
  g_threadcount -= 1;
  pthread_mutex_unlock(&g_threadcount_lock);
  free(kkeys);

  return NULL;
}

void *crack4(void *param) {
  (void)(param); /* Silence unused warning. */
  pthread_mutex_lock(&g_threadcount_lock);
  g_threadcount++;
  pthread_mutex_unlock(&g_threadcount_lock);

  /* Precalculate tweaks. */
  uint32_t r1tw = (g_tw1 >> 40);
  uint32_t r4tw = (g_tw1 >> 32) & 0xffffff;
  uint8_t tw1 = g_tw1 >> 56;
  uint8_t tw4 = (g_tw1 >> 32) & 0xff;
  uint8_t tw5 = (g_tw1 >> 24) & 0xff;
  uint8_t tw6 = (g_tw1 >> 16) & 0xff;
  uint8_t tw7 = (g_tw1 >> 8) & 0xff;

  uint32_t k12;
  while ((k12 = get_next()) < 0x10000) {
    uint8_t k2 = k12 & 0xff;
    for (uint32_t k345 = 0; k345 < 0x1000000; k345++) {
      uint32_t k123 = (k12 << 8) | (k345 >> 16);
      uint32_t r1ct = enc_one_round(g_pt1, k123 ^ r1tw);
      uint32_t r3ct = dec_one_round(g_ct1, k345 ^ r4tw);
      uint8_t k4 = (k345 >> 8) & 0xff;
      uint8_t k5 = k345 & 0xff;
      uint8_t app = r3ct >> 16;
      uint8_t bpp = (r3ct >> 8) & 0xff;
      uint8_t cpp = r3ct & 0xff;
      uint8_t a = r1ct >> 16;
      uint8_t b = (r1ct >> 8) & 0xff;
      uint8_t c = r1ct & 0xff;
      uint8_t ap = g_sbox_enc[a ^ b ^ k4 ^ tw4];
      uint8_t cp = g_sbox_enc[b ^ c ^ k5 ^ tw5];
      uint8_t bp = g_sbox_dec[bpp] ^ app ^ cpp ^ k2 ^ tw1;
      uint8_t k6 = g_sbox_dec[bp] ^ ap ^ b ^ cp ^ tw6;
      uint8_t k7 = g_sbox_dec[app] ^ ap ^ bp ^ tw7;
      uint64_t kkey = ((uint64_t)k123 << 32) | ((uint64_t)k4) << 24 | ((uint64_t)k5) << 16
          | ((uint64_t)k6) << 8 | k7;
      if (encrypt_lattice(4, g_pt2, kkey, g_tw2) == g_ct2) {
        if (g_pt3 == (uint32_t)-1 || encrypt_lattice(4, g_pt3, kkey, g_tw3) == g_ct3) {
          pthread_mutex_lock(&g_write_lock);
          fprintf(g_outfp, "%014" PRIx64 "\n", kkey);
          g_keysfound += 1;
          pthread_mutex_unlock(&g_write_lock);
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

  void *(*crack_func)(void*) = NULL;
  switch (atoi(argv[1])) {
    case 3:
      crack_func = crack3;
      break;
    case 4:
      crack_func = crack4;
      break;
    default:
      fprintf(stderr, "Bad number of rounds. Only 3 and 4 rounds are supported.\n");
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
    g_pt3 = strtol(argv[9], NULL, 16);
    g_ct3 = strtol(argv[10], NULL, 16);
    g_tw3 = strtoll(argv[11], NULL, 16);
    printf("PT3: %06" PRIx32 " CT3: %06" PRIx32 " TW3: %016" PRIx64 "\n", g_pt3, g_ct3, g_tw3);
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
