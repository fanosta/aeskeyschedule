#!/usr/bin/env python3

import argparse
from binascii import hexlify, unhexlify
from aeskeyschedule import key_schedule, reverse_key_schedule

import sys

try:
    import colorama
    colorama.init()
    __highlight = colorama.Style.BRIGHT
    __reset = colorama.Style.RESET_ALL
except ImportError:
    __highlight = ''
    __reset = ''


def aes_round(value: str) -> int:
    aes_round = int(value)
    if not 0 <= aes_round <= 10:
        raise argparse.ArgumentError('the aes round must satisfy 0 <= r <= 10')
    return aes_round

def aes_key(value: str) -> bytes:
    if value.startswith('0x'):
        value = value[2:]
    try:
        key = unhexlify(value)
    except TypeError:
        raise argparse.ArgumentError('invalid hex bytes in aes key')
    if len(key) * 8 not in {128, 192, 256}:
        raise argparse.ArgumentError('''
            AES key must be 128, 192 or 256 bits long (is {} bits)
            '''.strip().format(len(key) * 8))
    return key


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='''
        Tool to calculate the Rijndael key schedule given any AES-128 round key.
        '''.strip())
    parser.add_argument('-r', '--round', dest='aes_round', default=0, type=aes_round, help='''
        The AES round of the provided key. Defaults to 0 (base key).
        '''.strip())
    parser.add_argument('round_key', type=aes_key, help='''
        the round key in hex notation from which the full key will be derived.
        '''.strip())
    return parser.parse_args()


def __main(aes_round: int, round_key: bytes) -> None:
    if len(round_key) * 8 != 128 and aes_round != 0:
        print("reversing the AES-{} key schedule is not supported".format(len(base_key) * 8, file=sys.stderr))
        sys.exit(1)


    if aes_round != 0:
        base_key = reverse_key_schedule(aes_round, round_key)
    else:
        base_key = round_key
    keys = key_schedule(base_key)

    assert keys[aes_round] == round_key or len(base_key) * 8 != 128

    for i, key in enumerate(keys):
        if i == aes_round:
            print(__highlight, end='')
        print("{:2}: {}".format(i, hexlify(key).decode()))
        if i == aes_round:
            print(__reset, end='')

def main():
    args = parse_args()
    __main(**vars(args))

if __name__ == '__main__':
    main()
