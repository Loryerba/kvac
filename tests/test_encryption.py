import pytest

import kvac

# Hardcoded constants from libsignal
TEST_ARRAY_16 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]

TEST_ARRAY_32 = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
]

# Hardcoded constants from previously (hopefully) correct implementation
SYSTEM_HARDCODED = [
    0x34, 0x6f, 0x08, 0xef, 0xd1, 0x68, 0x74, 0x67, 0x18, 0xd9, 0x16, 0xba, 0x40, 0x61, 0xf6,
    0x11, 0x71, 0x0d, 0x04, 0x4c, 0x31, 0x7b, 0xe5, 0x0a, 0x48, 0x8b, 0x14, 0x4c, 0x38, 0xcc,
    0x72, 0x4b, 0xc0, 0xa4, 0x49, 0xbb, 0x62, 0xe7, 0x78, 0x98, 0x49, 0xae, 0x32, 0x9a, 0xa0,
    0xcc, 0x44, 0xad, 0x34, 0x70, 0xdc, 0x78, 0xf6, 0x52, 0x85, 0x66, 0x98, 0x69, 0xee, 0x0f,
    0x80, 0xb4, 0x80, 0x77,
]

SYSTEM_HARDCODED_63 = [
    0x34, 0x6f, 0x08, 0xef, 0xd1, 0x68, 0x74, 0x67, 0x18, 0xd9, 0x16, 0xba, 0x40, 0x61, 0xf6,
    0x11, 0x71, 0x0d, 0x04, 0x4c, 0x31, 0x7b, 0xe5, 0x0a, 0x48, 0x8b, 0x14, 0x4c, 0x38, 0xcc,
    0x72, 0x4b, 0xc0, 0xa4, 0x49, 0xbb, 0x62, 0xe7, 0x78, 0x98, 0x49, 0xae, 0x32, 0x9a, 0xa0,
    0xcc, 0x44, 0xad, 0x34, 0x70, 0xdc, 0x78, 0xf6, 0x52, 0x85, 0x66, 0x98, 0x69, 0xee, 0x0f,
    0x80, 0xb4, 0x80,
]

SYSTEM_HARDCODED_65 = [
    0x34, 0x6f, 0x08, 0xef, 0xd1, 0x68, 0x74, 0x67, 0x18, 0xd9, 0x16, 0xba, 0x40, 0x61, 0xf6,
    0x11, 0x71, 0x0d, 0x04, 0x4c, 0x31, 0x7b, 0xe5, 0x0a, 0x48, 0x8b, 0x14, 0x4c, 0x38, 0xcc,
    0x72, 0x4b, 0xc0, 0xa4, 0x49, 0xbb, 0x62, 0xe7, 0x78, 0x98, 0x49, 0xae, 0x32, 0x9a, 0xa0,
    0xcc, 0x44, 0xad, 0x34, 0x70, 0xdc, 0x78, 0xf6, 0x52, 0x85, 0x66, 0x98, 0x69, 0xee, 0x0f,
    0x80, 0xb4, 0x80, 0x77, 0x77,
]

CIPHERTEXT_HARDCODED = [
    0x88, 0xe8, 0x83, 0xdf, 0x23, 0xfc, 0xa7, 0x4c, 0xca, 0x9d, 0x00, 0x14, 0xa6, 0xea, 0x58,
    0xbf, 0x1d, 0xb3, 0x8f, 0x2c, 0xcb, 0xa9, 0x80, 0xf5, 0x1f, 0xc3, 0x3a, 0x14, 0x79, 0x3e,
    0x02, 0x18, 0x64, 0xed, 0x2e, 0x39, 0xfc, 0xf9, 0x5d, 0x00, 0x85, 0x69, 0x64, 0x18, 0x6e,
    0xbf, 0x46, 0xd3, 0xb5, 0x42, 0x0d, 0x4b, 0xff, 0xec, 0xb4, 0xf0, 0xf3, 0xce, 0x3e, 0xb9,
    0x0d, 0x44, 0xbb, 0x5e
]


def test_encryption():
    # Testing system parameters
    # ==============================================================================================
    system_label = b'Signal_ZKGroup_20200424_Constant_UidEncryption_SystemParams_Generate'
    # Generate system and check if it's the same as the one previously generated with this
    # system label
    system = kvac.EncryptionSystemParams.generate(system_label)
    assert system == kvac.EncryptionSystemParams.from_bytes(bytes(SYSTEM_HARDCODED))

    # Check if tyring to decode 63 bytes raises a DeserializationFailure
    with pytest.raises(kvac.DeserializationFailure):
        kvac.EncryptionSystemParams.from_bytes(bytes(SYSTEM_HARDCODED_63))
    # Check if tyring to decode 65 bytes raises a DeserializationFailure
    with pytest.raises(kvac.DeserializationFailure):
        kvac.EncryptionSystemParams.from_bytes(bytes(SYSTEM_HARDCODED_65))
    # ==============================================================================================

    # Testing key pairs
    # ==============================================================================================
    # Derive a key pair for that system from a master key
    master_key = bytes(TEST_ARRAY_32)
    key_pair = kvac.KeyPair.derive_from(system, master_key)
    # Convert key pair to bytes and check if they are the same after conversion
    key_pair_bytes = bytes(key_pair)
    key_pair2 = kvac.KeyPair.from_bytes(key_pair_bytes)
    assert key_pair == key_pair2
    # Check if tyring to decode 95 bytes raises a DeserializationFailure
    with pytest.raises(kvac.DeserializationFailure):
        kvac.EncryptionSystemParams.from_bytes(key_pair_bytes[0:95])
    # Check if tyring to decode 96 bytes raises a DeserializationFailure
    with pytest.raises(kvac.DeserializationFailure):
        kvac.EncryptionSystemParams.from_bytes(key_pair_bytes+bytes(1))
    # ==============================================================================================

    # Testing specific encryption/decryption rigorously
    # ==============================================================================================
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
        kvac.EncryptionSystemParams.from_bytes(ciphertext_bytes[0:63])
    # Check if tyring to decode 63 bytes raises a DeserializationFailure
    with pytest.raises(kvac.DeserializationFailure):
        kvac.EncryptionSystemParams.from_bytes(ciphertext_bytes+bytes(1))
    # Check if the ciphertext bytes are the same as a previous encryption of this ciphertext
    assert ciphertext_bytes == bytes(CIPHERTEXT_HARDCODED)
    # Decrypt the ciphertext and check if it is the same as the original uid
    plaintext = key_pair.decrypt(ciphertext2)
    assert plaintext == m
    # ==============================================================================================

    # Test repeated encryption and decryption
    # ==============================================================================================
    sho = kvac.RistrettoSho(b'Test_Repeated_Encryption', b'seed')
    for _ in range(100):
        m = bytes(sho.squeeze(16))
        assert m == key_pair.decrypt(key_pair.encrypt(m))
    # ==============================================================================================

    # Test encryption and decryption of increasingly longer messages if only messages with 16 bytes
    # can be encrypted
    # ==============================================================================================
    sho = kvac.RistrettoSho(b'Test_Repeated_Encryption', b'seed')
    for i in range(100):
        m = bytes(sho.squeeze(i))

        if i != 16:
            with pytest.raises(ValueError):
                key_pair.decrypt(key_pair.encrypt(m))
        else:
            assert m == key_pair.decrypt(key_pair.encrypt(m))
    # ==============================================================================================

    # Test repeated encryption and decryption for different systems
    # ==============================================================================================
    sho = kvac.RistrettoSho(b'Test_Repeated_Encryption_Various_Systems', b'seed')
    for _ in range(100):
        system_label = bytes(sho.squeeze(32))
        system = kvac.EncryptionSystemParams.generate(system_label)
        master_key = bytes(sho.squeeze(32))
        key_pair = kvac.KeyPair.derive_from(system, master_key)
        m = bytes(sho.squeeze(16))
        assert m == key_pair.decrypt(key_pair.encrypt(m))
    # ==============================================================================================
