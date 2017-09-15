/* sodark.h

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

#ifndef _SODARK_H_
#define _SODARK_H_

#include <inttypes.h>
#include <stdbool.h>

/* Lookup tables for the SoDark s-box. */
bool g_sbox_dec_init = false; /* Set to true by create_sodark_dec_sbox. */
uint32_t g_sbox_dec[256];
const uint32_t g_sbox_enc[] = {0x9c, 0xf2, 0x14, 0xc1, 0x8e, 0xcb, 0xb2, 0x65,
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

/* Initializes the SoDark decryption S-box. */
static inline void create_sodark_dec_sbox() {
  /* Fill lookup table for the inverse s-box. */
  for (uint16_t i = 0; i < 256; i++) {
    g_sbox_dec[g_sbox_enc[i]] = i;
  }
  g_sbox_dec_init = true;
}

/* Do one round of encryption with the SoDark-3 algorithm.
   pt   Plaintext (24 bits).
   rkey Round key, i.e. three key bytes xored with three bytes of tweak. */
static inline uint32_t enc_one_round_3(uint32_t pt, uint32_t rkey) {
  uint32_t pa =  pt >> 16;
  uint32_t pb = (pt >> 8) & 0xff;
  uint32_t pc =  pt & 0xff;
  uint32_t ka =  rkey >> 16;
  uint32_t kc = (rkey >> 8) & 0xff;
  uint32_t kb =  rkey & 0xff;
  uint32_t ca = g_sbox_enc[pa ^ pb ^ ka];
  uint32_t cc = g_sbox_enc[pc ^ pb ^ kc];
  uint32_t cb = g_sbox_enc[ca ^ pb ^ cc ^ kb];
  return (ca << 16) | (cb << 8) | cc;
}

/* Do one round of decryption with the SoDark-3 algorithm.
   ct   Ciphertext (24 bits).
   rkey Round key, i.e. three key bytes xored with three bytes of tweak. */
static inline uint32_t dec_one_round_3(uint32_t ct, uint32_t rkey) {
  if (!g_sbox_dec_init) {
    create_sodark_dec_sbox();
  }
  uint32_t ca = ct >> 16;
  uint32_t cb = (ct >> 8) & 0xff;
  uint32_t cc = ct & 0xff;
  uint32_t ka = rkey >> 16;
  uint32_t kc = (rkey >> 8) & 0xff;
  uint32_t kb = rkey & 0xff;
  uint32_t pb = g_sbox_dec[cb] ^ ca ^ cc ^ kb;
  uint32_t pc = g_sbox_dec[cc] ^ pb ^ kc;
  uint32_t pa = g_sbox_dec[ca] ^ pb ^ ka;
  return (pa << 16) | (pb << 8) | pc;
}

/* Do one round of encryption with the SoDark-6 algorithm.
   pt   Plaintext (48 bits).
   rkey Round key, i.e. six key bytes xored with six bytes of tweak. */
static inline uint64_t enc_one_round_6(uint64_t pt, uint64_t rkey) {
  uint64_t pa =  pt >> 40;
  uint64_t pb = (pt >> 32) & 0xff;
  uint64_t pc = (pt >> 24) & 0xff;
  uint64_t pd = (pt >> 16) & 0xff;
  uint64_t pe = (pt >> 8)  & 0xff;
  uint64_t pf =  pt & 0xff;
  uint64_t ka =  rkey >> 40;
  uint64_t kc = (rkey >> 32) & 0xff;
  uint64_t ke = (rkey >> 24) & 0xff;
  uint64_t kb = (rkey >> 16) & 0xff;
  uint64_t kd = (rkey >> 8)  & 0xff;
  uint64_t kf =  rkey & 0xff;
  uint64_t ca = g_sbox_enc[pa ^ pb ^ pf ^ ka];
  uint64_t cc = g_sbox_enc[pb ^ pc ^ pd ^ kc];
  uint64_t ce = g_sbox_enc[pd ^ pe ^ pf ^ ke];
  uint64_t cb = g_sbox_enc[ca ^ pb ^ cc ^ kb];
  uint64_t cd = g_sbox_enc[cc ^ pd ^ ce ^ kd];
  uint64_t cf = g_sbox_enc[ca ^ pf ^ ce ^ kf];

  return (ca << 40) | (cb << 32) | (cc << 24) | (cd << 16) | (ce << 8) | cf;
}

/* Do one round of decryption with the SoDark-6 algorithm.
   ct   Ciphertext (48 bits).
   rkey Round key, i.e. six key bytes xored with six bytes of tweak. */
static inline uint64_t dec_one_round_6(uint64_t ct, uint64_t rkey) {
  if (!g_sbox_dec_init) {
    create_sodark_dec_sbox();
  }
  uint64_t ca =  ct >> 40;
  uint64_t cb = (ct >> 32) & 0xff;
  uint64_t cc = (ct >> 24) & 0xff;
  uint64_t cd = (ct >> 16) & 0xff;
  uint64_t ce = (ct >> 8)  & 0xff;
  uint64_t cf =  ct & 0xff;
  uint64_t ka =  rkey >> 40;
  uint64_t kc = (rkey >> 32) & 0xff;
  uint64_t ke = (rkey >> 24) & 0xff;
  uint64_t kb = (rkey >> 16) & 0xff;
  uint64_t kd = (rkey >> 8)  & 0xff;
  uint64_t kf =  rkey & 0xff;
  uint64_t pb = g_sbox_dec[cb] ^ ca ^ cc ^ kb;
  uint64_t pd = g_sbox_dec[cd] ^ cc ^ ce ^ kd;
  uint64_t pf = g_sbox_dec[cf] ^ ca ^ ce ^ kf;
  uint64_t pa = g_sbox_dec[ca] ^ pb ^ pf ^ ka;
  uint64_t pc = g_sbox_dec[cc] ^ pb ^ pd ^ kc;
  uint64_t pe = g_sbox_dec[ce] ^ pd ^ pf ^ ke;

  return (pa << 40) | (pb << 32) | (pc << 24) | (pd << 16) | (pe << 8) | pf;
}

/* Encrypt using the the Sodark-3 algorithm.
   rounds Number of rounds.
   pt     Plaintext (24 bits).
   key    Encryption key (56 bits).
   tweak  Tweak (64 bits). */
static inline uint32_t encrypt_sodark_3(uint32_t rounds, uint32_t pt, uint64_t key,
    uint64_t tweak) {
  uint32_t ct = pt;
  for (uint32_t round = 0; round < rounds; round++) {
    uint32_t rkey = ((key >> 32) ^ (tweak >> 40)) & 0xffffff;
    tweak = (tweak << 24) | (tweak >> 40);
    key = ((key << 24) | (key >> 32)) & 0xffffffffffffffL;
    ct = enc_one_round_3(ct, rkey);
  }
  return ct;
}

/* Decrypt using the the Sodark-3 algorithm.
   rounds Number of rounds.
   ct     Ciphertext (24 bits).
   key    Encryption key (56 bits).
   tweak  Tweak (64 bits). */
static inline uint32_t decrypt_sodark_3(uint32_t rounds, uint32_t ct, uint64_t key,
    uint64_t tweak) {
  if (!g_sbox_dec_init) {
    create_sodark_dec_sbox();
  }
  uint32_t tshift = (24 * (rounds - 1)) % 64;
  uint32_t kshift = (24 * (rounds - 1)) % 56;
  tweak = (tweak >> (64 - tshift)) | (tweak << tshift);
  key = ((key >> (56 - kshift)) | (key << kshift)) & 0xffffffffffffffL;
  uint32_t pt = ct;
  for (uint32_t round = 0; round < rounds; round++) {
    uint32_t rkey = ((key >> 32) ^ (tweak >> 40)) & 0xffffff;
    tweak = (tweak >> 24) | (tweak << 40);
    key = ((key >> 24) | (key << 32)) & 0xffffffffffffffL;
    pt = dec_one_round_3(pt, rkey);
  }
  return pt;
}

/* Encrypt using the the Sodark-6 algorithm.
   rounds Number of rounds.
   pt     Plaintext (48 bits).
   key    Encryption key (56 bits).
   tweak  Tweak (64 bits). */
static inline uint64_t encrypt_sodark_6(uint32_t rounds, uint64_t pt, uint64_t key,
    uint64_t tweak) {
  uint64_t ct = pt;
  for (uint32_t round = 0; round < rounds; round++) {
    uint64_t rkey = ((key >> 8) ^ (tweak >> 16)) % 0xffffffffffffL;
    tweak = (tweak << 48) | (tweak >> 16);
    key = ((key << 48) | (key >> 8)) & 0xffffffffffffffL;
    ct = enc_one_round_6(ct, rkey);
  }
  return ct;
}

/* Decrypt using the the Sodark-6 algorithm.
   rounds Number of rounds.
   ct     Ciphertext (48 bits).
   key    Encryption key (56 bits).
   tweak  Tweak (64 bits). */
static inline uint64_t decrypt_sodark_6(uint32_t rounds, uint64_t ct, uint64_t key,
    uint64_t tweak) {
  if (!g_sbox_dec_init) {
    create_sodark_dec_sbox();
  }
  uint32_t tshift = (48 * (rounds - 1)) % 64;
  uint32_t kshift = (48 * (rounds - 1)) % 56;
  tweak = (tweak >> (64 - tshift)) | (tweak << tshift);
  key = ((key >> (56 - kshift)) | (key << kshift)) & 0xffffffffffffffL;
  uint64_t pt = ct;
  for (uint32_t round = 0; round < rounds; round++) {
    uint64_t rkey = ((key >> 8) ^ (tweak >> 16)) & 0xffffffffffffL;
    tweak = (tweak >> 48) | (tweak << 16);
    key = ((key >> 48) | (key << 8)) & 0xffffffffffffffL;
    pt = dec_one_round_6(pt, rkey);
  }
  return pt;
}

#endif /* _SODARK_H_ */
