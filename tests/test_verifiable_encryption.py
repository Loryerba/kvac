import random

import pytest

from kvac.verifiable_encryption import EncryptionParams, KeyPair, AttributeRepresentationForEncryption, \
    DeserializationFailure, Ciphertext, MessageToEncrypt
from kvac.ristretto_sho import RistrettoSho

# Hardcoded constants from libsignal
TEST_ARRAY_16 = list(range(16))
TEST_ARRAY_17 = list(range(17))

TEST_ARRAY_32 = list(range(32))

# Hardcoded constants from previously (hopefully) correct implementation
SYSTEM_HARDCODED = [
    0x8a, 0x6a, 0x8d, 0xe5, 0x6b, 0x32, 0x59, 0xdf, 0x0b, 0x34, 0x43, 0x58, 0xf3, 0xbe, 0x23,
    0x53, 0x20, 0xfa, 0xc6, 0x12, 0x63, 0xbf, 0xe5, 0x6d, 0xf7, 0x17, 0x91, 0xe6, 0xc6, 0xd1,
    0x15, 0x33, 0x7c, 0xdf, 0x37, 0x82, 0x9d, 0x5d, 0x0d, 0x6a, 0xb5, 0x63, 0x09, 0x01, 0x3d,
    0x8d, 0x89, 0x01, 0xe6, 0x15, 0x35, 0xec, 0xcd, 0x6a, 0xad, 0x06, 0x43, 0x1d, 0xfb, 0xdd,
    0x40, 0xa4, 0x7f, 0x26,
]

SYSTEM_HARDCODED_63 = [
    0x8a, 0x6a, 0x8d, 0xe5, 0x6b, 0x32, 0x59, 0xdf, 0x0b, 0x34, 0x43, 0x58, 0xf3, 0xbe, 0x23,
    0x53, 0x20, 0xfa, 0xc6, 0x12, 0x63, 0xbf, 0xe5, 0x6d, 0xf7, 0x17, 0x91, 0xe6, 0xc6, 0xd1,
    0x15, 0x33, 0x7c, 0xdf, 0x37, 0x82, 0x9d, 0x5d, 0x0d, 0x6a, 0xb5, 0x63, 0x09, 0x01, 0x3d,
    0x8d, 0x89, 0x01, 0xe6, 0x15, 0x35, 0xec, 0xcd, 0x6a, 0xad, 0x06, 0x43, 0x1d, 0xfb, 0xdd,
    0x40, 0xa4, 0x7f,
]

SYSTEM_HARDCODED_65 = [
    0x8a, 0x6a, 0x8d, 0xe5, 0x6b, 0x32, 0x59, 0xdf, 0x0b, 0x34, 0x43, 0x58, 0xf3, 0xbe, 0x23,
    0x53, 0x20, 0xfa, 0xc6, 0x12, 0x63, 0xbf, 0xe5, 0x6d, 0xf7, 0x17, 0x91, 0xe6, 0xc6, 0xd1,
    0x15, 0x33, 0x7c, 0xdf, 0x37, 0x82, 0x9d, 0x5d, 0x0d, 0x6a, 0xb5, 0x63, 0x09, 0x01, 0x3d,
    0x8d, 0x89, 0x01, 0xe6, 0x15, 0x35, 0xec, 0xcd, 0x6a, 0xad, 0x06, 0x43, 0x1d, 0xfb, 0xdd,
    0x40, 0xa4, 0x7f, 0x26, 0x00
]

CIPHERTEXT_HARDCODED = [
    0xd4, 0xb6, 0x27, 0xea, 0xcb, 0x8e, 0xd1, 0x56, 0x0a, 0xd2, 0xc3, 0x5a, 0xa7, 0x1e, 0x0b,
    0xd5, 0xc8, 0x53, 0xc3, 0x25, 0x89, 0x78, 0x67, 0x08, 0x83, 0xc3, 0x2b, 0xa7, 0xb4, 0x6e,
    0x92, 0x6c, 0xd4, 0xfa, 0x16, 0x7a, 0x7f, 0xfa, 0x7e, 0x2d, 0xb6, 0x2b, 0xac, 0x68, 0x24,
    0xa8, 0x5f, 0x72, 0x0d, 0xc6, 0x38, 0xa4, 0xf5, 0x2f, 0xcb, 0xe1, 0x31, 0x9f, 0x96, 0xe3,
    0xa6, 0x5d, 0xef, 0x2c,
]

# pytest fixtures constantly redefine outer names, so ignore the warning.
# pylint: disable=redefined-outer-name

@pytest.fixture
def system(attribute_label):
    return EncryptionParams.generate(b'EncryptionParams_Generate', attribute_label)


@pytest.fixture
def attribute_label():
    return b'Test_Attribute'


@pytest.fixture
def master_key():
    return bytes(TEST_ARRAY_32)


def test_encryption_params(system):
    # Testing encryption parameters
    # ==============================================================================================
    # Generate system and check if it's the same as the one previously generated with this
    # system label
    assert system == EncryptionParams.from_bytes(bytes(SYSTEM_HARDCODED))

    # Check if tyring to decode 63 bytes raises a DeserializationFailure
    with pytest.raises(DeserializationFailure):
        EncryptionParams.from_bytes(bytes(SYSTEM_HARDCODED_63))
    # Check if tyring to decode 65 bytes raises a DeserializationFailure
    with pytest.raises(DeserializationFailure):
        EncryptionParams.from_bytes(bytes(SYSTEM_HARDCODED_65))


def test_key_pair(system, master_key, attribute_label):
    # Testing key pairs
    # ==============================================================================================
    # Derive a key pair for that system from a master key
    key_pair = KeyPair.derive_from(system, master_key, attribute_label)
    # Convert key pair to bytes and check if they are the same after conversion
    key_pair_bytes = bytes(key_pair)
    key_pair2 = KeyPair.from_bytes(key_pair_bytes)
    assert key_pair == key_pair2
    # Check if tyring to decode 95 bytes raises a DeserializationFailure
    with pytest.raises(DeserializationFailure):
        EncryptionParams.from_bytes(key_pair_bytes[0:95])
    # Check if tyring to decode 96 bytes raises a DeserializationFailure
    with pytest.raises(DeserializationFailure):
        EncryptionParams.from_bytes(key_pair_bytes + bytes(1))


def test_encryption(system, master_key, attribute_label):
    # Testing specific encryption/decryption rigorously
    # ==============================================================================================
    key_pair = KeyPair.derive_from(system, master_key, attribute_label)
    # Generate m and encrypt it
    m = bytes(TEST_ARRAY_16)
    hash_supplement = bytes(TEST_ARRAY_17)
    ciphertext = key_pair.encrypt(AttributeRepresentationForEncryption.encode(
        MessageToEncrypt(m, hash_supplement)
    ))
    # Convert ciphertext to bytes and check if they are the same after conversion
    ciphertext_bytes = bytes(ciphertext)
    assert len(ciphertext_bytes) == 64
    ciphertext2 = Ciphertext.from_bytes(ciphertext_bytes)
    assert ciphertext == ciphertext2
    # Check if tyring to decode 63 bytes raises a DeserializationFailure
    with pytest.raises(DeserializationFailure):
        EncryptionParams.from_bytes(ciphertext_bytes[0:63])
    # Check if tyring to decode 63 bytes raises a DeserializationFailure
    with pytest.raises(DeserializationFailure):
        EncryptionParams.from_bytes(ciphertext_bytes+bytes(1))
    # Check if the ciphertext bytes are the same as a previous encryption of this ciphertext
    assert ciphertext_bytes == bytes(CIPHERTEXT_HARDCODED)
    # Decrypt the ciphertext and check if it is the same as the original uid
    plaintext = key_pair.decrypt(ciphertext2, hash_supplement).decode()
    assert plaintext == m


def test_repeated_encryption(system, master_key, attribute_label):
    # Test repeated encryption and decryption
    # ==============================================================================================
    key_pair = KeyPair.derive_from(system, master_key, attribute_label)
    sho = RistrettoSho(b'Test_Repeated_Encryption', b'seed')
    for _ in range(100):
        m = bytes(sho.squeeze(16))
        hash_supplement = bytes(sho.squeeze(random.randint(0, 32)))
        assert m == key_pair.decrypt(
            key_pair.encrypt(AttributeRepresentationForEncryption.encode(
                MessageToEncrypt(m, hash_supplement)
            )),
            hash_supplement
        ).decode()


def test_message_sizes(system, master_key, attribute_label):
    # Test encryption and decryption of increasingly longer messages if only messages with 16 bytes
    # can be encrypted
    # ==============================================================================================
    key_pair = KeyPair.derive_from(system, master_key, attribute_label)
    sho = RistrettoSho(b'Message_Size_Encryption', b'seed')
    for i in range(100):
        m = bytes(sho.squeeze(i))
        hash_supplement = bytes(sho.squeeze(i))
        message_to_encrypt = MessageToEncrypt(m, hash_supplement)

        if i != 16:
            with pytest.raises(ValueError):
                key_pair.decrypt(
                    key_pair.encrypt(AttributeRepresentationForEncryption.encode(message_to_encrypt)),
                    hash_supplement
                )
        else:
            assert m == key_pair.decrypt(
                key_pair.encrypt(AttributeRepresentationForEncryption.encode(message_to_encrypt)),
                hash_supplement
            ).decode()


def test_random_systems():
    # Test repeated encryption and decryption for different systems
    # ==============================================================================================
    sho = RistrettoSho(b'Test_Repeated_Encryption_Various_Systems', b'seed')
    for _ in range(100):
        system_label = bytes(sho.squeeze(32))
        attribute_label = bytes(sho.squeeze(32))
        system = EncryptionParams.generate(system_label, attribute_label)
        master_key = bytes(sho.squeeze(32))
        key_pair = KeyPair.derive_from(system, master_key, attribute_label)
        m = bytes(sho.squeeze(16))
        hash_supplement = bytes(sho.squeeze(16))
        assert m == key_pair.decrypt(
            key_pair.encrypt(AttributeRepresentationForEncryption.encode(
                MessageToEncrypt(m, hash_supplement)
            )),
            hash_supplement
        ).decode()
