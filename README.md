[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.893134.svg)](https://doi.org/10.5281/zenodo.893134)

# SoCracked
Performs key-recovery attacks on the SoDark family of ciphers for automatic
link establishment (ALE) in HF radios specified in MIL-STD-188-141. Attacks on
up to five rounds are possible using virtually any two
plaintext-ciphertext-tweak tuples. Attacks on six and seven rounds require
tuples with tweaks that are identical in all but the fifth tweak byte.

## Build

```console
$ gcc -Ofast -march=native -lpthread socracked.c -o socracked
$ gcc -Ofast -march=native sodark.c -o sodark
```

## Run

For attacks on up to five rounds, the plaintext-ciphertext-tweak tuples are
specified on the command line. The following will perform a key recovery
attack on four rounds using the test vectors from the standard:
```console
$ ./socracked 4 keys.txt 54e0cd 987c6d 543bd88000017550 b2a7c5 53eda9 543bd88080017550
```
Matching keys are output to `keys.txt`. An optional third tuple can be
specified to reduce the number of keys found.

For six and seven rounds, which require a special internal differential for the
attack to work, the tuples are read from a text file. The file has three
columns, one each for plaintext, ciphertext, and tweak. For example:
```
8147ed c131f6 543bd88040017550
c28b9c c19af6 543bd88000017550
f31e21 51f614 543bd88040017550
f32186 b741bd 543bd88040017550
f3232f 3d5216 543bd88040017550
f32928 f1a786 543bd88040017550
f32f5f ceb446 543bd88000017550

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

`sodark -h` will display a brief help message.


## License

This project is licensed under the GNU General Public License -- see the [LICENSE](LICENSE)
file for details.
