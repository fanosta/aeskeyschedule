# AES key schedule tool
This tool can be used as either a python library or a command line tool

This project is available on pypi
```
pip3 install aeskeyschedule --user --upgrade
```

## Command Line Tool
```
usage: aeskeyschedule [-h] [-r AES_ROUND] round_key

Tool to calculate the Rijndael key schedule given any AES-128 round key.

positional arguments:
  round_key             the round key in hex notation from which the full key
                        will be derived.

optional arguments:
  -h, --help            show this help message and exit
  -r AES_ROUND, --round AES_ROUND
                        The AES round of the provided key. Defaults to 0 (base
                        key).
```
### Example Usage
View the AES expanded key given the base key
```
$ aeskeyschedule 00000000000000000000000000000000
 0: 00000000000000000000000000000000
 1: 62636363626363636263636362636363
 2: 9b9898c9f9fbfbaa9b9898c9f9fbfbaa
 3: 90973450696ccffaf2f457330b0fac99
 4: ee06da7b876a1581759e42b27e91ee2b
 5: 7f2e2b88f8443e098dda7cbbf34b9290
 6: ec614b851425758c99ff09376ab49ba7
 7: 217517873550620bacaf6b3cc61bf09b
 8: 0ef903333ba9613897060a04511dfa9f
 9: b1d4d8e28a7db9da1d7bb3de4c664941
10: b4ef5bcb3e92e21123e951cf6f8f188e
```

Reverse the AES-128 key schedule using the last round key

```
$ aeskeyschedule --round 10 002a5e9033d14c1f03ed911164b9be02
 0: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 1: 07060606adacacac07060606adacacac
 2: 94979793393b3b3f3e3d3d3993919195
 3: 1116bd4f282d86701610bb4985812adc
 4: 15f33bd83ddebda82bce06e1ae4f2c3d
 5: 81821c3cbc5ca1949792a77539dd8b48
 6: 60bf4e2edce3efba4b7148cf72acc387
 7: b191596e6d72b6d42603fe1b54af3d9c
 8: 48b6874e25c4319a03c7cf815768f21d
 9: 163f231533fb128f303cdd0e67542f13
10: 002a5e9033d14c1f03ed911164b9be02
```


## Python Library
The two main functions are `key_schedule` and `reverse_key_schedule`

Calculate the AES-128 base key given the last round key:
```python3
base_key = reverse_key_schedule(b'\xe2K\xbb"~\xe8\xb3\xe6u\x06_\xdb\x9b\xd6\x9bB', 10)
```

Calculate the last round key using an AES-128 base key:
```python3
base_key = b'\x91\xa3\xba\x04\xe3\xdb:\x10\xc7$R\x15|]\xca\x87'
expanded_key = key_schedule(base_key)
assert expanded_key[0] == base_key
last_round_key = expanded_key[10]
```
