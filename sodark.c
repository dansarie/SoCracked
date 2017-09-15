/* sodark

   Utility for encryption and decryption with the SoDark family of ciphers.

   Copyright (C) 2017 Marcus Dansarie <marcus@dansarie.se>

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sodark.h"

void printusage(char *name) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s mode rounds pt/ct key tweak\n", name);
  fprintf(stderr, "          -3d  SoDark-3 decryption\n");
  fprintf(stderr, "          -3e  SoDark-3 encryption\n");
  fprintf(stderr, "          -6d  SoDark-6 decryption\n");
  fprintf(stderr, "          -6e  SoDark-6 encryption\n");
  fprintf(stderr, "%s -r {3|6} rounds key tweak ntuples\n", name);
  fprintf(stderr, "          Generate ntuples random tuples.\n");
}

int main(int argc, char **argv) {
  create_sodark_dec_sbox();

  assert(enc_one_round_3(0x54e0cd, 0xc2284a ^ 0x543bd8) == 0xd0721d);
  assert(dec_one_round_3(0xd0721d, 0xc2284a ^ 0x543bd8) == 0x54e0cd);
  assert(dec_one_round_3(dec_one_round_3(0xd0721d, 0xc2284a ^ 0x543bd8), 0) == 0x2ac222);
  assert(dec_one_round_6(enc_one_round_6(0x1234567890ab, 0x6d7dddd48390), 0x6d7dddd48390)
      == 0x1234567890ab);
  assert(encrypt_sodark_3(3, 0x54e0cd, 0xc2284a1ce7be2f, 0x543bd88000017550) == 0x41db0c);
  assert(encrypt_sodark_3(4, 0x54e0cd, 0xc2284a1ce7be2f, 0x543bd88000017550) == 0x987c6d);
  assert(decrypt_sodark_3(1, 0xd0721d, 0xc2284a1ce7be2f, 0x543bd88000017550) == 0x54e0cd);
  assert(decrypt_sodark_3(3, 0x41db0c, 0xc2284a1ce7be2f, 0x543bd88000017550) == 0x54e0cd);
  assert(decrypt_sodark_3(4, 0x987c6d, 0xc2284a1ce7be2f, 0x543bd88000017550) == 0x54e0cd);
  assert(decrypt_sodark_6(1, encrypt_sodark_6(1, 0xdeafcafebabe, 0xc2284a1ce7be2f,
      0x543bd88000017550), 0xc2284a1ce7be2f, 0x543bd88000017550) == 0xdeafcafebabe);

  if (argc == 6) {
    uint32_t rounds = atoi(argv[2]);
    uint64_t pt_ct = strtoull(argv[3], NULL, 16);
    uint64_t key   = strtoull(argv[4], NULL, 16);
    uint64_t tweak = strtoull(argv[5], NULL, 16);

    if (rounds <= 0) {
      fprintf(stderr, "Bad number of rounds.\n\n");
      printusage(argv[0]);
      return 1;
    }

    printf("Rounds: %d\n", rounds);
    printf("PT/CT:  %012" PRIx64 "\n", pt_ct);
    printf("Key:    %014" PRIx64 "\n", key);
    printf("Tweak:  %016" PRIx64 "\n", tweak);

    if (strcmp(argv[1], "-3d") == 0) {
      printf("CT:     %06" PRIx32 "\n",  decrypt_sodark_3(rounds, (uint32_t)pt_ct, key, tweak));
    } else if (strcmp(argv[1], "-3e") == 0) {
      printf("CT:     %06" PRIx32 "\n",  encrypt_sodark_3(rounds, (uint32_t)pt_ct, key, tweak));
    } else if (strcmp(argv[1], "-6d") == 0) {
      printf("CT:     %012" PRIx64 "\n", decrypt_sodark_6(rounds, pt_ct, key, tweak));
    } else if (strcmp(argv[1], "-6e") == 0) {
      printf("CT:     %012" PRIx64 "\n", encrypt_sodark_6(rounds, pt_ct, key, tweak));
    } else {
      fprintf(stderr, "Bad mode.\n\n");
      printusage(argv[0]);
      return 1;
    }
  } else if (argc == 7) {
    if (strcmp(argv[1], "-r") != 0) {
      printusage(argv[0]);
      return 1;
    }
    uint32_t rounds = atoi(argv[3]);
    uint64_t key    = strtoull(argv[4], NULL, 16);
    uint64_t tweak  = strtoull(argv[5], NULL, 16);
    uint32_t tuples = atoi(argv[6]);

    FILE *randp = fopen("/dev/urandom", "r");
    if (randp == NULL) {
      fprintf(stderr, "Error when opening /dev/urandom.\n");
      return 1;
    }

    if (strcmp(argv[2], "3") == 0) {
      fprintf(stderr, "Generating %d random tuples with SoDark-3.\n", tuples);
      fprintf(stderr, "Rounds: %d\n", rounds);
      fprintf(stderr, "Key:    %014" PRIx64 "\n", key);
      fprintf(stderr, "Tweak:  %016" PRIx64 "\n", tweak);
      uint32_t pt;
      for (int i = 0; i < tuples; i++) {
        if (fread(&pt, sizeof(uint32_t), 1, randp) != 1) {
          fprintf(stderr, "Error when reading from /dev/urandom.\n");
          fclose(randp);
          return 1;
        }
        pt &= 0xffffff;
        uint32_t ct = encrypt_sodark_3(rounds, pt, key, tweak);
        printf("%06x %06x %016" PRIx64 "\n", pt, ct, tweak);
      }
    } else if (strcmp(argv[2], "6") == 0) {
      fprintf(stderr, "Generating %d random tuples with SoDark-6.\n", tuples);
      fprintf(stderr, "Rounds: %d\n", rounds);
      fprintf(stderr, "Key:    %014" PRIx64 "\n", key);
      fprintf(stderr, "Tweak:  %016" PRIx64 "\n", tweak);
      uint64_t pt;
      for (int i = 0; i < tuples; i++) {
        if (fread(&pt, sizeof(uint32_t), 1, randp) != 1) {
          fprintf(stderr, "Error when reading from /dev/urandom.\n");
          fclose(randp);
          return 1;
        }
        pt &= 0xffffffffffffL;
        uint64_t ct = encrypt_sodark_6(rounds, pt, key, tweak);
        printf("%012" PRIx64 " %012" PRIx64 " %016" PRIx64 "\n", pt, ct, tweak);
      }
    } else {
      printusage(argv[0]);
      fclose(randp);
      return 1;
    }
    fclose(randp);
  } else {
    printusage(argv[0]);
    return 1;
  }

  return 0;
}
