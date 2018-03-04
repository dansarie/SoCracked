/* dimacs2key

   Extracts the key from solution to SAT problem instances generated with
   lattice2dimacs.

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

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
   uint64_t key = 0;
   uint64_t known = 0;

   bool verbose = false;
   if (argc == 2 && strcmp(argv[1], "-v") == 0) {
      verbose = true;
   }

   char *lineptr = NULL;
   size_t len = 0;
   while (getline(&lineptr, &len, stdin) > 0) {
      if (verbose) {
         printf("%s", lineptr);
      }
      if (lineptr[0] != 'v') {
         continue;
      }
      char *token = strtok(lineptr, " ");
      while (token != NULL) {
         int var = atoi(token);
         if (var != 0 && abs(var) <= 56) {
            uint64_t mask = (uint64_t)1 << (56 - abs(var));
            known |= mask;
            if (var > 0) {
               key |= mask;
            } else {
               key &= ~mask;
            }
            if (known == 0xffffffffffffffL) {
               printf("%014" PRIx64 "\n", key);
               known = key = 0;
            }
         }
         token = strtok(NULL, " ");
      }
   }
   free(lineptr);
   return 0;
}
