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
