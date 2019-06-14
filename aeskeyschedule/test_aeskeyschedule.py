#!/usr/bin/env python3

import pytest

from .aeskeyschedule import key_schedule, reverse_key_schedule
from binascii import unhexlify

from typing import List

test_vectors_128 = [
    [
        '00000000000000000000000000000000',
        '62636363626363636263636362636363',
        '9b9898c9f9fbfbaa9b9898c9f9fbfbaa',
        '90973450696ccffaf2f457330b0fac99',
        'ee06da7b876a1581759e42b27e91ee2b',
        '7f2e2b88f8443e098dda7cbbf34b9290',
        'ec614b851425758c99ff09376ab49ba7',
        '217517873550620bacaf6b3cc61bf09b',
        '0ef903333ba9613897060a04511dfa9f',
        'b1d4d8e28a7db9da1d7bb3de4c664941',
        'b4ef5bcb3e92e21123e951cf6f8f188e',
    ],
    [
        'ffffffffffffffffffffffffffffffff',
        'e8e9e9e917161616e8e9e9e917161616',
        'adaeae19bab8b80f525151e6454747f0',
        '090e2277b3b69a78e1e7cb9ea4a08c6e',
        'e16abd3e52dc2746b33becd8179b60b6',
        'e5baf3ceb766d488045d385013c658e6',
        '71d07db3c6b6a93bc2eb916bd12dc98d',
        'e90d208d2fbb89b6ed5018dd3c7dd150',
        '96337366b988fad054d8e20d68a5335d',
        '8bf03f233278c5f366a027fe0e0514a3',
        'd60a3588e472f07b82d2d7858cd7c326',
    ],
    [
        '000102030405060708090a0b0c0d0e0f',
        'd6aa74fdd2af72fadaa678f1d6ab76fe',
        'b692cf0b643dbdf1be9bc5006830b3fe',
        'b6ff744ed2c2c9bf6c590cbf0469bf41',
        '47f7f7bc95353e03f96c32bcfd058dfd',
        '3caaa3e8a99f9deb50f3af57adf622aa',
        '5e390f7df7a69296a7553dc10aa31f6b',
        '14f9701ae35fe28c440adf4d4ea9c026',
        '47438735a41c65b9e016baf4aebf7ad2',
        '549932d1f08557681093ed9cbe2c974e',
        '13111d7fe3944a17f307a78b4d2b30c5',
    ],
    [
        '6920e299a5202a6d656e636869746f2a',
        'fa8807605fa82d0d3ac64e6553b2214f',
        'cf75838d90ddae80aa1be0e5f9a9c1aa',
        '180d2f1488d0819422cb6171db62a0db',
        'baed96ad323d173910f67648cb94d693',
        '881b4ab2ba265d8baad02bc36144fd50',
        'b34f195d096944d6a3b96f15c2fd9245',
        'a7007778ae6933ae0dd05cbbcf2dcefe',
        'ff8bccf251e2ff5c5c32a3e7931f6d19',
        '24b7182e7555e77229674495ba78298c',
        'ae127cdadb479ba8f220df3d4858f6b1',
    ],
]

test_vectors_192 = [
    [
        '00000000000000000000000000000000',
        '00000000000000006263636362636363',
        '62636363626363636263636362636363',
        '9b9898c9f9fbfbaa9b9898c9f9fbfbaa',
        '9b9898c9f9fbfbaa90973450696ccffa',
        'f2f457330b0fac9990973450696ccffa',
        'c81d19a9a171d65353858160588a2df9',
        'c81d19a9a171d6537bebf49bda9a22c8',
        '891fa3a8d1958e51198897f8b8f941ab',
        'c26896f718f2b43f91ed1797407899c6',
        '59f00e3ee1094f9583ecbc0f9b1e0830',
        '0af31fa74a8b8661137b885ff272c7ca',
        '432ac886d834c0b6d2c7df11984c5970',
    ],
    [
        'ffffffffffffffffffffffffffffffff',
        'ffffffffffffffffe8e9e9e917161616',
        'e8e9e9e917161616e8e9e9e917161616',
        'adaeae19bab8b80f525151e6454747f0',
        'adaeae19bab8b80fc5c2d8ed7f7a60e2',
        '2d2b3104686c76f4c5c2d8ed7f7a60e2',
        '1712403f686820dd454311d92d2f672d',
        'e8edbfc09797df228f8cd3b7e7e4f36a',
        'a2a7e2b38f88859e67653a5ef0f2e57c',
        '2655c33bc1b130516316d2e2ec9e577c',
        '8bfb6d227b09885e67919b1aa620ab4b',
        'c53679a929a82ed5a25343f7d95acba9',
        '598e482fffaee3643a989acd1330b418',
    ],
    [
        '000102030405060708090a0b0c0d0e0f',
        '10111213141516175846f2f95c43f4fe',
        '544afef55847f0fa4856e2e95c43f4fe',
        '40f949b31cbabd4d48f043b810b7b342',
        '58e151ab04a2a5557effb5416245080c',
        '2ab54bb43a02f8f662e3a95d66410c08',
        'f501857297448d7ebdf1c6ca87f33e3c',
        'e510976183519b6934157c9ea351f1e0',
        '1ea0372a995309167c439e77ff12051e',
        'dd7e0e887e2fff68608fc842f9dcc154',
        '859f5f237a8d5a3dc0c02952beefd63a',
        'de601e7827bcdf2ca223800fd8aeda32',
        'a4970a331a78dc09c418c271e3a41d5d',
    ],
]

test_vectors_256 = [
    [
        '00000000000000000000000000000000',
        '00000000000000000000000000000000',
        '62636363626363636263636362636363',
        'aafbfbfbaafbfbfbaafbfbfbaafbfbfb',
        '6f6c6ccf0d0f0fac6f6c6ccf0d0f0fac',
        '7d8d8d6ad77676917d8d8d6ad7767691',
        '5354edc15e5be26d31378ea23c38810e',
        '968a81c141fcf7503c717a3aeb070cab',
        '9eaa8f28c0f16d45f1c6e3e7cdfe62e9',
        '2b312bdf6acddc8f56bca6b5bdbbaa1e',
        '6406fd52a4f79017553173f098cf1119',
        '6dbba90b0776758451cad331ec71792f',
        'e7b0e89c4347788b16760b7b8eb91a62',
        '74ed0ba1739b7e252251ad14ce20d43b',
        '10f80a1753bf729c45c979e7cb706385',
    ],
    [
        'ffffffffffffffffffffffffffffffff',
        'ffffffffffffffffffffffffffffffff',
        'e8e9e9e917161616e8e9e9e917161616',
        '0fb8b8b8f04747470fb8b8b8f0474747',
        '4a4949655d5f5f73b5b6b69aa2a0a08c',
        '355858dcc51f1f9bcaa7a7233ae0e064',
        'afa80ae5f2f755964741e30ce5e14380',
        'eca0421129bf5d8ae318faa9d9f81acd',
        'e60ab7d014fde24653bc014ab65d42ca',
        'a2ec6e658b5333ef684bc946b1b3d38b',
        '9b6c8a188f91685edc2d69146a702bde',
        'a0bd9f782beeac9743a565d1f216b65a',
        'fc22349173b35ccfaf9e35dbc5ee1e05',
        '0695ed132d7b41846ede24559cc8920f',
        '546d424f27de1e8088402b5b4dae355e',
    ],
    [
        '000102030405060708090a0b0c0d0e0f',
        '101112131415161718191a1b1c1d1e1f',
        'a573c29fa176c498a97fce93a572c09c',
        '1651a8cd0244beda1a5da4c10640bade',
        'ae87dff00ff11b68a68ed5fb03fc1567',
        '6de1f1486fa54f9275f8eb5373b8518d',
        'c656827fc9a799176f294cec6cd5598b',
        '3de23a75524775e727bf9eb45407cf39',
        '0bdc905fc27b0948ad5245a4c1871c2f',
        '45f5a66017b2d387300d4d33640a820a',
        '7ccff71cbeb4fe5413e6bbf0d261a7df',
        'f01afafee7a82979d7a5644ab3afe640',
        '2541fe719bf500258813bbd55a721c0a',
        '4e5a6699a9f24fe07e572baacdf8cdea',
        '24fc79ccbf0979e9371ac23c6d68de36',
    ],
]

def unhex(l: List[str]) -> List[bytes]:
    return [unhexlify(x) for x in l]


@pytest.mark.parametrize("testvector", test_vectors_128)
def test_aes_128(testvector: List[str]) -> None:
    round_keys_ref = unhex(testvector)
    round_keys = key_schedule(round_keys_ref[0])
    assert len(round_keys) == 11
    assert len(round_keys) == len(round_keys_ref)
    for got, expected in zip(round_keys, round_keys_ref):
        assert got == expected


@pytest.mark.parametrize("testvector", test_vectors_192)
def test_aes_192(testvector: List[str]) -> None:
    round_keys_ref = unhex(testvector)
    round_keys = key_schedule(b"".join([round_keys_ref[0], round_keys_ref[1][:8]]))
    assert len(round_keys) == 13
    assert len(round_keys) == len(round_keys_ref)
    for got, expected in zip(round_keys, round_keys_ref):
        assert got == expected

@pytest.mark.parametrize("testvector", test_vectors_256)
def test_aes_256(testvector: List[str]) -> None:
    round_keys_ref = unhex(testvector)
    round_keys = key_schedule(b"".join([round_keys_ref[0], round_keys_ref[1]]))
    assert len(round_keys) == 15
    assert len(round_keys) == len(round_keys_ref)
    for got, expected in zip(round_keys, round_keys_ref):
        assert got == expected


@pytest.mark.parametrize("testvector", test_vectors_128)
def test_aes_128_reverse(testvector: List[str]) -> None:
    round_keys_ref = unhex(testvector)

    for round_num, rk in enumerate(round_keys_ref):
        base_key = reverse_key_schedule(rk, round_num)
        assert base_key == round_keys_ref[0]
