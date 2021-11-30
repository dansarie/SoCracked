# SoCracked

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.893133.svg)](https://doi.org/10.5281/zenodo.893133)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Build Status](https://travis-ci.com/dansarie/SoCracked.svg?branch=master)](https://travis-ci.com/github/dansarie/SoCracked)
[![Coverage Status](https://coveralls.io/repos/github/dansarie/SoCracked/badge.svg)](https://coveralls.io/github/dansarie/SoCracked)

![Screenshot](screenshot.png?raw=true)

SoCracked performs key-recovery attacks on the SoDark family of ciphers for
automatic link establishment (ALE) in HF radios specified in MIL-STD-188-141.
Attacks on up to five rounds are possible using virtually any two
plaintext-ciphertext-tweak tuples. Attacks on six, seven, and eight rounds
require tuples with tweaks that are identical in all but the fifth tweak byte.
For an in-depth description of the techniques used, see
[Cryptanalysis of the SoDark family of cipher algorithms](https://doi.org/10945/56118).
The attacks on six, seven, and eight rounds have been implemented in CUDA as
well as in C. Brute force attacks on up to sixteen rounds have also been
implemented in CUDA.

In addition to the attacks described above, the programs `lattice2dimacs` and
`dimacs2key` generate SAT problem instances from sets of
plaintext-ciphertext-tweak tuples and convert the solutions back to keys in hex
format. The number of rounds that can be successfully attacked depends on the
SAT solver used.

## Dependencies

* [CMake](https://cmake.org/) (build system)
* CUDA (optional, enables brute force cracking)
* [msgpack](https://github.com/msgpack/msgpack-c) (for generating SAT solver
  instances with `lattice2dimacs`)
* ncurses

## Clone and build

```
sudo apt-get -y install cmake git libmsgpack-dev libncurses-dev
git clone https://github.com/dansarie/SoCracked.git
cd SoCracked
git submodule init
git submodule update
mkdir build
cd build
cmake ..
make
make install
```

## Clone and build with Docker

SoCracked can also be built to run from a Docker image. For GPU cracking with CUDA, the appropriate
drivers must be installed on the host system.

```
sudo apt-get -y install docker.io git
git clone https://github.com/dansarie/SoCracked.git
cd SoCracked
git submodule init
git submodule update
docker build -t socracked .
```

The following command mounts the current working directory on the host to the `/work` directory in
a docker container. From there, any of the commands described below can be run.

```
docker run -it --rm -v "$(pwd)":/work socracked /bin/bash
```

## Test

Running the script `test-socracked.sh` will test that cracking works as intended in all supported
use cases.

## Run

The program takes three command line arguments: the number of rounds, a file
containing input tuples, and an output file where the found keys will be stored.
The input file has three columns, one each for plaintext, ciphertext, and tweak.
For example:
```
8147ed c131f6 543bd88040017550
c28b9c c19af6 543bd88000017550
f31e21 51f614 543bd88040017550
f32186 b741bd 543bd88040017550
f3232f 3d5216 543bd88040017550
f32928 f1a786 543bd88040017550
f32f5f ceb446 543bd88000017550
```
The following will perform a key recovery attack on four rounds using the test
vectors from the standard and output the matching keys to `keys.txt`:
```
socracked 4 test/test4.txt keys.txt
```

### SoDark command line utility

The `sodark` utility can be used to perform encryption and decryption with any
number of rounds. For example:
```
sodark -3e 4 54e0cd c2284a1ce7be2f 543bd88000017550
```

It can also be used to generate random plaintexts for testing. The following
will generate 100 plaintext-ciphertext-tweak tuples with the common key
`c2284a1ce7be2f` and tweak `543bd88000017550`.

```
sodark -r 3 7 c2284a1ce7be2f 543bd88000017550 100
```

### Chosen-ciphertext attack

SoCracked can perform chosen-ciphertext attacks on eight rounds.
Chosen-ciphertext input to SoCracked has seven columns: plaintext 1,
ciphertext 1, tweak 1, plaintext 2, ciphertext 2, tweak 2, and the value of key
byte `k3`. For example:
```
2b40bf f1c485 c2edcba49aa69513 a0411b a62f81 c2edcba41ba69513 00
b3ad64 f1ad85 c2edcba49aa69513 204048 a60a81 c2edcba41ba69513 01
45822e f1ed85 c2edcba49aa69513 738b42 a67181 c2edcba41ba69513 02
115cf4 f1b085 c2edcba49aa69513 a6df4d a67381 c2edcba41ba69513 03
ec8f3c f13885 c2edcba49aa69513 60279e a68481 c2edcba41ba69513 04
85ab8b f1d085 c2edcba49aa69513 1d6207 a6a981 c2edcba41ba69513 05
```
The argument `-c` to the `sodark` utility can be used to generate 256
chosen-ciphertext pairs for a specific key.

To launch a chosen-ciphertext attack, SoCracked is called with `-c` instead of
the number of rounds:
```
socracked -c chosen.txt keys.txt
```

### SAT problem instance generation

SAT problem instances are generated with `lattice2dimacs` and solutions are
converted back to keys in hex format with `dimacs2key`. The following will
convert the plaintext-ciphertext-tweak tuples in
[test/test3.txt](test/test3.txt) to a SAT problem instance in DIMACS format,
pipe the output to a SAT solver and print the found keys to the console:

```
lattice2dimacs 3 3 sbox-cnf/8-366-3219-65213470-9db07eac.cnf test/test3.txt | sat_solver | ./dimacs2key
```

The command line arguments for `lattice2dimacs` are, in order:
* SoDark version: 3 or 6;
* number of rounds;
* a S-box CNF file generated with [sboxgates](https://github.com/dansarie/sboxgates); and
* a file with plaintext-ciphertext-tweak tuples in the same format as described above.

## License

This project is licensed under the GNU General Public License — see the [LICENSE](LICENSE)
file for details.
