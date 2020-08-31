/* socracked.h

   Copyright (C) 2018, 2020 Marcus Dansarie <marcus@dansarie.se>

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

#ifndef __SOCKRACKED_H__
#define __SOCKRACKED_H__
#include <stdint.h>

#define CHOSEN_CIPHERTEXT (0xffffffff)

#ifdef __cplusplus
extern "C" {
#endif

  extern bool g_exit; /* Indicates that the worker threads should shut down. */

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
    uint32_t k3[256];
    uint32_t num_k3;
  } pair_t;

  /* An array of tuple-pairs, with some associated data.
     Used by functions init_pairs, free_pairs, and add_pair. */
  typedef struct {
    pair_t *pairs;
    int allocsize;
    int allocstep;
    int num_pairs;
  } pairs_t;

  typedef struct {
    tuple_t *tuples;
    uint32_t num_tuples;
    uint32_t nrounds;
    int allocsize;
    int allocstep;
  } worker_param_t;

  /* Returns the next work unit when cracking 6, 7, or 8 rounds. Returns false to indicate that
     there are no more work units available and that the thread should stop. */
  bool get_next_678(uint32_t threadid, uint32_t *k12, pair_t **pair);

  /* Tests a candidate key against all known tuples. Returns true if the key is
     a match for all of them. */
  bool test_key(uint32_t rounds, uint64_t key, tuple_t *tuples, uint32_t num_tuples);

  /* Called by a cracking thread to write a found key to file and to update the
     number of keys found.*/
  void found_key(uint64_t key);

  /* Gets the status line in the user interface. */
  void set_status(const char *status);

#ifdef __cplusplus
}
#endif
#endif /* __SOCKRACKED_H__ */
