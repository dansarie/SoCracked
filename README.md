[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.893134.svg)](https://doi.org/10.5281/zenodo.893134)

# SoCracked
Performs key-recovery attacks on the SoDark family of ciphers for automatic
link establishment (ALE) in HF radios specified in MIL-STD-188-141. Attacks on
up to five rounds are possible using virtually any two
plaintext-ciphertext-tweak tuples. Attacks on six and seven rounds require
tuples with tweaks that are identical in all but the fifth tweak byte.

## Build

```console
$ gcc -Ofast -march=native -pthread socracked.c -o socracked
$ gcc -Ofast -march=native sodark.c -o sodark
```

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
```console
$ ./socracked 4 test/test4.txt keys.txt
```

The `sodark` utility can be used to perform encryption and decryption with any
number of rounds. For example:
```console
$ ./sodark -3e 4 54e0cd c2284a1ce7be2f 543bd88000017550
```

It can also be used to generate random plaintexts for testing. The following
will generate 100 plaintext-ciphertext-tweak tuples with the common key
`c2284a1ce7be2f` and tweak `543bd88000017550`.

```console
$ ./sodark -r 3 7 c2284a1ce7be2f 543bd88000017550 100
```

## License

This project is licensed under the GNU General Public License -- see the [LICENSE](LICENSE)
file for details.
