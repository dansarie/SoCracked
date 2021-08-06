/* lattice2dimacs

   Convert SoDark plaintext-ciphertext-tweak tuples into their CNF
   representations and print them to stdout in DIMACS format.

   Copyright (C) 2018 Marcus Dansarie <marcus@dansarie.se>

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

#include "sboxgates/state.h"

#define MAX_VARIABLES 10
#define ALLOC_STEP 1000

typedef struct {
  int variables[MAX_VARIABLES];
} clause_t;

typedef struct {
  int bits[8];
} byte_t;

typedef struct {
  clause_t *clauses;
  int next_var;
  int num_clauses;
  int clauses_alloc;
} cnf_repr_t;

static void init_cnf_repr(cnf_repr_t *st) {
  st->clauses = malloc(sizeof(clause_t) * ALLOC_STEP);
  st->next_var = 1;
  st->num_clauses = 0;
  st->clauses_alloc = ALLOC_STEP;
}

static void free_cnf_repr(cnf_repr_t *st) {
  free(st->clauses);
  st->next_var = 1;
  st->num_clauses = 0;
  st->clauses_alloc = 0;
}

static void init_clause(clause_t *cl) {
  memset(cl->variables, 0, sizeof(int) * MAX_VARIABLES);
}

static void add_clause(cnf_repr_t *st, clause_t cl) {
  if (st->num_clauses == st->clauses_alloc) {
    st->clauses_alloc += ALLOC_STEP;
    st->clauses = realloc(st->clauses, sizeof(clause_t) * st->clauses_alloc);
  }
  st->clauses[st->num_clauses++] = cl;
}

static int add_operation(gate_type op, cnf_repr_t *st, int in1, int in2) {
  int out = st->next_var++;
  int variables[] = {0, in1, in2, out};
  int *clauses;

  int not_clauses[]    = {-1, -3,  0,
                           1,  3,  0,
                           0,  0,  0,
                           0,  0,  0};
  int and_clauses[]    = {-1, -2,  3,
                           1, -3,  0,
                           2, -3,  0,
                           0,  0,  0};
  int or_clauses[]     = { 1,  2, -3,
                          -1,  3,  0,
                          -2,  3,  0,
                           0,  0,  0};
  int xor_clauses[]    = {-1, -2, -3,
                           1,  2, -3,
                           1, -2,  3,
                          -1,  2,  3};
  int andnot_clauses[] = { 1, -2,  3,
                          -1, -3,  0,
                           2, -3,  0,
                           0,  0,  0};

  switch (op) {
    case NOT:
      clauses = not_clauses;
      break;
    case AND:
      clauses = and_clauses;
      break;
    case OR:
      clauses = or_clauses;
      break;
    case XOR:
      clauses = xor_clauses;
      break;
    case A_AND_NOT_B:
      clauses = andnot_clauses;
      break;
    default:
      assert(0);
  }

  clause_t cl;
  for (int i = 0; i < 4; i++) {
    if (clauses[i * 3] == 0 || clauses[i * 3 + 1] == 0) {
      continue;
    }
    init_clause(&cl);
    cl.variables[0] = variables[abs(clauses[i * 3])]     * (clauses[i * 3]     < 0 ? -1 : 1);
    cl.variables[1] = variables[abs(clauses[i * 3 + 1])] * (clauses[i * 3 + 1] < 0 ? -1 : 1);
    cl.variables[2] = variables[abs(clauses[i * 3 + 2])] * (clauses[i * 3 + 2] < 0 ? -1 : 1);
    add_clause(st, cl);
  }
  return out;
}

static byte_t add_key_and_tweak(cnf_repr_t *st, byte_t in, byte_t key, uint8_t tweak) {
  byte_t out;
  clause_t cl;
  init_clause(&cl);
  for (int i = 0; i < 8; i++) {
    int mul = (tweak >> i) & 1 ? -1 : 1;
    out.bits[i] = st->next_var++;
    cl.variables[0] = -in.bits[i];
    cl.variables[1] = -key.bits[i];
    cl.variables[2] = -out.bits[i] * mul;
    add_clause(st, cl);
    cl.variables[0] =  in.bits[i];
    cl.variables[1] =  key.bits[i];
    cl.variables[2] = -out.bits[i] * mul;
    add_clause(st, cl);
    cl.variables[0] =  in.bits[i];
    cl.variables[1] = -key.bits[i];
    cl.variables[2] =  out.bits[i] * mul;
    add_clause(st, cl);
    cl.variables[0] = -in.bits[i];
    cl.variables[1] =  key.bits[i];
    cl.variables[2] =  out.bits[i] * mul;
    add_clause(st, cl);
  }
  return out;
}

static byte_t add_byte_operation(gate_type op, cnf_repr_t *st, byte_t in1, byte_t in2) {
  byte_t out;
  for (int i = 0; i < 8; i++) {
    out.bits[i] = add_operation(op, st, in1.bits[i], in2.bits[i]);
  }
  return out;
}

static byte_t sbox_byte(cnf_repr_t *st, state sbox, byte_t in1) {
  int gatenums[MAX_GATES];
  for (int i = 0; i < 8; i++) {
    gatenums[i] = in1.bits[i];
  }
  for (int i = 8; i < sbox.num_gates; i++) {
    gatenums[i] = add_operation(sbox.gates[i].type, st, gatenums[sbox.gates[i].in1],
        sbox.gates[i].in2 == NO_GATE ? 0 : gatenums[sbox.gates[i].in2]);
  }
  byte_t out;
  for (int i = 0; i < 8; i++) {
    out.bits[i] = gatenums[sbox.outputs[i]];
  }
  return out;
}

int main(int argc, char *argv[]) {

  if (argc != 5) {
    fprintf(stderr, "Bad number of arguments.\n");
    fprintf(stderr, "Usage: %s 3/6 rounds sbox-cnf infile\n", argv[0]);
    return 1;
  }

  int algorithm = atoi(argv[1]);
  if (algorithm != 3 && algorithm != 6) {
    fprintf(stderr, "Bad algorithm version: %d. Must be 3 or 6.\n", algorithm);
    return 1;
  }

  int nrounds = atoi(argv[2]);
  if (nrounds < 1) {
    fprintf(stderr, "Bad number of rounds: %d\n", nrounds);
    return 1;
  }

  state sbox;
  if (!load_state(argv[3], &sbox)) {
    fprintf(stderr, "Could not load sbox cnf file: %s\n", argv[3]);
    return 1;
  }

  FILE *infp = fopen(argv[4], "r");
  if (infp == NULL) {
    fprintf(stderr, "Could not open input file: %s\n", argv[4]);
    return 1;
  }

  printf("c %d rounds SoDark-%d\n", nrounds, algorithm);
  printf("c S-box CNF file: %s\n", argv[3]);
  printf("c Input file: %s\n", argv[4]);

  cnf_repr_t cnf;
  init_cnf_repr(&cnf);

  /* Assign variables to the key bits. */
  byte_t key_bytes[7];
  for (int i = 0; i < 7; i++) {
    for (int k = 7; k >= 0; k--) {
      key_bytes[i].bits[k] = cnf.next_var++;
    }
  }

  /* Loop over all tuples in the input file. */
  while (!feof(infp)) {
    uint64_t pt;
    uint64_t ct;
    uint64_t tw;
    if (algorithm == 3) {
      if (fscanf(infp, "%06" PRIx64 " %06" PRIx64 " %016" PRIx64 "\n", &pt, &ct, &tw) != 3) {
        continue;
      }
      printf("c PT: %06" PRIx64 " CT: %06" PRIx64 " TW: %016" PRIx64 "\n", pt, ct, tw);
    } else {
      if (fscanf(infp, "%012" PRIx64 " %012" PRIx64 " %016" PRIx64 "\n", &pt, &ct, &tw) != 3) {
        continue;
      }
      printf("c PT: %012" PRIx64 " CT: %012" PRIx64 " TW: %016" PRIx64 "\n", pt, ct, tw);
    }

    uint8_t tweak_bytes[8];
    for (int i = 0; i < 8; i++) {
      tweak_bytes[i] = (tw >> (56 - 8 * i)) & 0xff;
    }

    /* Add known plaintext clauses. */
    byte_t ci_state[6];
    clause_t cl;
    init_clause(&cl);
    int offs = algorithm == 3 ? 16 : 40;
    for (int i = 0; i < algorithm; i++) {
      for (int k = 7; k >= 0; k--) {
        ci_state[i].bits[k] = cnf.next_var++;
        cl.variables[0] = ci_state[i].bits[k] * ((pt >> (offs + k)) & 1 ? 1 : -1);
        add_clause(&cnf, cl);
      }
      offs -= 8;
    }

    int next_key_byte = 0;
    int next_tweak_byte = 0;
    for (int round = 0; round < nrounds; round++) {
      if (algorithm == 3) {
        ci_state[0] = add_byte_operation(XOR, &cnf, ci_state[0], ci_state[1]); /* a xor b */
        ci_state[0] = add_key_and_tweak(&cnf, ci_state[0], key_bytes[next_key_byte],
            tweak_bytes[next_tweak_byte]);                                     /* a xor k xor tw */
        next_key_byte = (next_key_byte + 1) % 7;
        next_tweak_byte = (next_tweak_byte + 1) % 8;
        ci_state[0] = sbox_byte(&cnf, sbox, ci_state[0]);                      /* sbox(a) */

        ci_state[2] = add_byte_operation(XOR, &cnf, ci_state[2], ci_state[1]); /* c xor b */
        ci_state[2] = add_key_and_tweak(&cnf, ci_state[2], key_bytes[next_key_byte],
            tweak_bytes[next_tweak_byte]);                                     /* c xor k xor tw */
        next_key_byte = (next_key_byte + 1) % 7;
        next_tweak_byte = (next_tweak_byte + 1) % 8;
        ci_state[2] = sbox_byte(&cnf, sbox, ci_state[2]);                      /* sbox(c) */

        ci_state[1] = add_byte_operation(XOR, &cnf, ci_state[1], ci_state[0]); /* b xor a */
        ci_state[1] = add_byte_operation(XOR, &cnf, ci_state[1], ci_state[2]); /* b xor c */
        ci_state[1] = add_key_and_tweak(&cnf, ci_state[1], key_bytes[next_key_byte],
            tweak_bytes[next_tweak_byte]);                                     /* b xor k xor tw */
        next_key_byte = (next_key_byte + 1) % 7;
        next_tweak_byte = (next_tweak_byte + 1) % 8;
        ci_state[1] = sbox_byte(&cnf, sbox, ci_state[1]);                      /* sbox(b) */
      } else {
        ci_state[0] = add_byte_operation(XOR, &cnf, ci_state[0], ci_state[1]); /* a xor b */
        ci_state[0] = add_byte_operation(XOR, &cnf, ci_state[0], ci_state[5]); /* a xor f */
        ci_state[0] = add_key_and_tweak(&cnf, ci_state[0], key_bytes[next_key_byte],
            tweak_bytes[next_tweak_byte]);                                     /* a xor k xor tw */
        next_key_byte = (next_key_byte + 1) % 7;
        next_tweak_byte = (next_tweak_byte + 1) % 8;
        ci_state[0] = sbox_byte(&cnf, sbox, ci_state[0]);                      /* sbox(a) */

        ci_state[2] = add_byte_operation(XOR, &cnf, ci_state[2], ci_state[1]); /* c xor b */
        ci_state[2] = add_byte_operation(XOR, &cnf, ci_state[2], ci_state[3]); /* c xor d */
        ci_state[2] = add_key_and_tweak(&cnf, ci_state[2], key_bytes[next_key_byte],
            tweak_bytes[next_tweak_byte]);                                     /* c xor k xor tw */
        next_key_byte = (next_key_byte + 1) % 7;
        next_tweak_byte = (next_tweak_byte + 1) % 8;
        ci_state[2] = sbox_byte(&cnf, sbox, ci_state[2]);                      /* sbox(c) */

        ci_state[4] = add_byte_operation(XOR, &cnf, ci_state[4], ci_state[3]); /* e xor d */
        ci_state[4] = add_byte_operation(XOR, &cnf, ci_state[4], ci_state[5]); /* e xor f */
        ci_state[4] = add_key_and_tweak(&cnf, ci_state[4], key_bytes[next_key_byte],
            tweak_bytes[next_tweak_byte]);                                     /* e xor k xor tw */
        next_key_byte = (next_key_byte + 1) % 7;
        next_tweak_byte = (next_tweak_byte + 1) % 8;
        ci_state[4] = sbox_byte(&cnf, sbox, ci_state[4]);                      /* sbox(e) */

        ci_state[1] = add_byte_operation(XOR, &cnf, ci_state[1], ci_state[0]); /* b xor a */
        ci_state[1] = add_byte_operation(XOR, &cnf, ci_state[1], ci_state[2]); /* b xor c */
        ci_state[1] = add_key_and_tweak(&cnf, ci_state[1], key_bytes[next_key_byte],
            tweak_bytes[next_tweak_byte]);                                     /* b xor k xor tw */
        next_key_byte = (next_key_byte + 1) % 7;
        next_tweak_byte = (next_tweak_byte + 1) % 8;
        ci_state[1] = sbox_byte(&cnf, sbox, ci_state[1]);                      /* sbox(b) */

        ci_state[3] = add_byte_operation(XOR, &cnf, ci_state[3], ci_state[2]); /* d xor c */
        ci_state[3] = add_byte_operation(XOR, &cnf, ci_state[3], ci_state[4]); /* d xor e */
        ci_state[3] = add_key_and_tweak(&cnf, ci_state[3], key_bytes[next_key_byte],
            tweak_bytes[next_tweak_byte]);                                     /* d xor k xor tw */
        next_key_byte = (next_key_byte + 1) % 7;
        next_tweak_byte = (next_tweak_byte + 1) % 8;
        ci_state[3] = sbox_byte(&cnf, sbox, ci_state[3]);                      /* sbox(d) */

        ci_state[5] = add_byte_operation(XOR, &cnf, ci_state[5], ci_state[4]); /* f xor e */
        ci_state[5] = add_byte_operation(XOR, &cnf, ci_state[5], ci_state[0]); /* f xor a */
        ci_state[5] = add_key_and_tweak(&cnf, ci_state[5], key_bytes[next_key_byte],
            tweak_bytes[next_tweak_byte]);                                     /* f xor k xor tw */
        next_key_byte = (next_key_byte + 1) % 7;
        next_tweak_byte = (next_tweak_byte + 1) % 8;
        ci_state[5] = sbox_byte(&cnf, sbox, ci_state[5]);                      /* sbox(f) */
      }
    }

    /* Add known ciphertext clauses. */
    offs = algorithm == 3 ? 16 : 40;
    for (int i = 0; i < algorithm; i++) {
      for (int k = 7; k >= 0; k--) {
        cl.variables[0] = ci_state[i].bits[k] * ((ct >> (offs + k)) & 1 ? 1 : -1);
        add_clause(&cnf, cl);
      }
      offs -= 8;
    }
  }
  fclose(infp);

  /* Convert clauses to DIMACS format. */
  printf("p cnf %d %d\n", cnf.next_var - 1, cnf.num_clauses);
  for (int i = 0; i < cnf.num_clauses; i++) {
    int k = 0;
    do {
      printf("%s%d", k == 0 ? "" : " ", cnf.clauses[i].variables[k]);
    } while (cnf.clauses[i].variables[k++] != 0);
    printf("\n");
  }

  free_cnf_repr(&cnf);
  return 0;
}
