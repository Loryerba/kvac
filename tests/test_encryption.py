import pytest

import kvac

# Hardcoded constants from libsignal
TEST_ARRAY_16 = list(range(16))

TEST_ARRAY_32 = list(range(32))

# Hardcoded constants from previously (hopefully) correct implementation
SYSTEM_HARDCODED = [
    0xf4, 0x21, 0xfa, 0x85, 0x15, 0x2c, 0xf9, 0xb6, 0x42, 0x25, 0xea, 0x16, 0xcb, 0x23, 0xca,
    0x84, 0x01, 0xcb, 0x70, 0x5d, 0x07, 0x5a, 0xc9, 0x00, 0x6c, 0x85, 0xca, 0xdb, 0xd9, 0x60,
    0xc2, 0x1a, 0x34, 0x2c, 0xaf, 0x6e, 0x20, 0xfd, 0x51, 0xbc, 0xd4, 0x5b, 0x3c, 0x35, 0xbd,
    0x39, 0x53, 0xfa, 0x33, 0xd0, 0x90, 0x18, 0xeb, 0xa6, 0x1d, 0x4d, 0x95, 0xd7, 0xd3, 0x30,
    0x0d, 0x42, 0xfe, 0x47,
]

SYSTEM_HARDCODED_63 = [
    0xf4, 0x21, 0xfa, 0x85, 0x15, 0x2c, 0xf9, 0xb6, 0x42, 0x25, 0xea, 0x16, 0xcb, 0x23, 0xca,
    0x84, 0x01, 0xcb, 0x70, 0x5d, 0x07, 0x5a, 0xc9, 0x00, 0x6c, 0x85, 0xca, 0xdb, 0xd9, 0x60,
    0xc2, 0x1a, 0x34, 0x2c, 0xaf, 0x6e, 0x20, 0xfd, 0x51, 0xbc, 0xd4, 0x5b, 0x3c, 0x35, 0xbd,
    0x39, 0x53, 0xfa, 0x33, 0xd0, 0x90, 0x18, 0xeb, 0xa6, 0x1d, 0x4d, 0x95, 0xd7, 0xd3, 0x30,
    0x0d, 0x42, 0xfe,
]

SYSTEM_HARDCODED_65 = [
    0xf4, 0x21, 0xfa, 0x85, 0x15, 0x2c, 0xf9, 0xb6, 0x42, 0x25, 0xea, 0x16, 0xcb, 0x23, 0xca,
    0x84, 0x01, 0xcb, 0x70, 0x5d, 0x07, 0x5a, 0xc9, 0x00, 0x6c, 0x85, 0xca, 0xdb, 0xd9, 0x60,
    0xc2, 0x1a, 0x34, 0x2c, 0xaf, 0x6e, 0x20, 0xfd, 0x51, 0xbc, 0xd4, 0x5b, 0x3c, 0x35, 0xbd,
    0x39, 0x53, 0xfa, 0x33, 0xd0, 0x90, 0x18, 0xeb, 0xa6, 0x1d, 0x4d, 0x95, 0xd7, 0xd3, 0x30,
    0x0d, 0x42, 0xfe, 0x47, 0x00,
]

CIPHERTEXT_HARDCODED = [
    0x88, 0xe8, 0x83, 0xdf, 0x23, 0xfc, 0xa7, 0x4c, 0xca, 0x9d, 0x00, 0x14, 0xa6, 0xea, 0x58,
    0xbf, 0x1d, 0xb3, 0x8f, 0x2c, 0xcb, 0xa9, 0x80, 0xf5, 0x1f, 0xc3, 0x3a, 0x14, 0x79, 0x3e,
    0x02, 0x18, 0x64, 0xed, 0x2e, 0x39, 0xfc, 0xf9, 0x5d, 0x00, 0x85, 0x69, 0x64, 0x18, 0x6e,
    0xbf, 0x46, 0xd3, 0xb5, 0x42, 0x0d, 0x4b, 0xff, 0xec, 0xb4, 0xf0, 0xf3, 0xce, 0x3e, 0xb9,
    0x0d, 0x44, 0xbb, 0x5e
]


def test_encryption_params():
    # Testing encryption parameters
    # ==============================================================================================
    system_label = b'EncryptionParams_Generate'
    # Generate system and check if it's the same as the one previously generated with this
    # system label
    system = kvac.EncryptionParams.generate(system_label)
    assert system == kvac.EncryptionParams.from_bytes(bytes(SYSTEM_HARDCODED))

    # Check if tyring to decode 63 bytes raises a DeserializationFailure
    with pytest.raises(kvac.DeserializationFailure):
        kvac.EncryptionParams.from_bytes(bytes(SYSTEM_HARDCODED_63))
    # Check if tyring to decode 65 bytes raises a DeserializationFailure
    with pytest.raises(kvac.DeserializationFailure):
        kvac.EncryptionParams.from_bytes(bytes(SYSTEM_HARDCODED_65))


def test_key_pair():
    # Testing key pairs
    # ==============================================================================================
    system_label = b'EncryptionParams_Generate'
    system = kvac.EncryptionParams.generate(system_label)
    master_key = bytes(TEST_ARRAY_32)
    # Derive a key pair for that system from a master key
    key_pair = kvac.KeyPair.derive_from(system, master_key)
    # Convert key pair to bytes and check if they are the same after conversion
    key_pair_bytes = bytes(key_pair)
    key_pair2 = kvac.KeyPair.from_bytes(key_pair_bytes)
    assert key_pair == key_pair2
    # Check if tyring to decode 95 bytes raises a DeserializationFailure
    with pytest.raises(kvac.DeserializationFailure):
        kvac.EncryptionParams.from_bytes(key_pair_bytes[0:95])
    # Check if tyring to decode 96 bytes raises a DeserializationFailure
    with pytest.raises(kvac.DeserializationFailure):
        kvac.EncryptionParams.from_bytes(key_pair_bytes + bytes(1))


def test_encryption():
    # Testing specific encryption/decryption rigorously
    # ==============================================================================================
    system_label = b'EncryptionParams_Generate'
    system = kvac.EncryptionParams.generate(system_label)
    master_key = bytes(TEST_ARRAY_32)
    key_pair = kvac.KeyPair.derive_from(system, master_key)
    # Generate m and encrypt it
    m = bytes(TEST_ARRAY_16)
    ciphertext = key_pair.encrypt(m)
    # Convert ciphertext to bytes and check if they are the same after conversion
    ciphertext_bytes = bytes(ciphertext)
    assert len(ciphertext_bytes) == 64
    ciphertext2 = kvac.Ciphertext.from_bytes(ciphertext_bytes)
    assert ciphertext == ciphertext2
    # Check if tyring to decode 63 bytes raises a DeserializationFailure
    with pytest.raises(kvac.DeserializationFailure):
        kvac.EncryptionParams.from_bytes(ciphertext_bytes[0:63])
    # Check if tyring to decode 63 bytes raises a DeserializationFailure
    with pytest.raises(kvac.DeserializationFailure):
        kvac.EncryptionParams.from_bytes(ciphertext_bytes+bytes(1))
    # Check if the ciphertext bytes are the same as a previous encryption of this ciphertext
    assert ciphertext_bytes == bytes(CIPHERTEXT_HARDCODED)
    # Decrypt the ciphertext and check if it is the same as the original uid
    plaintext = key_pair.decrypt(ciphertext2)
    assert plaintext == m


def test_repeated_encryption():
    # Test repeated encryption and decryption
    # ==============================================================================================
    system_label = b'Repeated_Encryption_EncryptionParams'
    system = kvac.EncryptionParams.generate(system_label)
    master_key = bytes(TEST_ARRAY_32)
    key_pair = kvac.KeyPair.derive_from(system, master_key)
    sho = kvac.RistrettoSho(b'Test_Repeated_Encryption', b'seed')
    for _ in range(100):
        m = bytes(sho.squeeze(16))
        assert m == key_pair.decrypt(key_pair.encrypt(m))


def test_message_sizes():
    # Test encryption and decryption of increasingly longer messages if only messages with 16 bytes
    # can be encrypted
    # ==============================================================================================
    system_label = b'Message_Size_EncryptionParams'
    system = kvac.EncryptionParams.generate(system_label)
    master_key = bytes(TEST_ARRAY_32)
    key_pair = kvac.KeyPair.derive_from(system, master_key)
    sho = kvac.RistrettoSho(b'Message_Size_Encryption', b'seed')
    for i in range(100):
        m = bytes(sho.squeeze(i))

        if i != 16:
            with pytest.raises(ValueError):
                key_pair.decrypt(key_pair.encrypt(m))
        else:
            assert m == key_pair.decrypt(key_pair.encrypt(m))


def test_random_systems():
    # Test repeated encryption and decryption for different systems
    # ==============================================================================================
    sho = kvac.RistrettoSho(b'Test_Repeated_Encryption_Various_Systems', b'seed')
    for _ in range(100):
        system_label = bytes(sho.squeeze(32))
        system = kvac.EncryptionParams.generate(system_label)
        master_key = bytes(sho.squeeze(32))
        key_pair = kvac.KeyPair.derive_from(system, master_key)
        m = bytes(sho.squeeze(16))
        assert m == key_pair.decrypt(key_pair.encrypt(m))
