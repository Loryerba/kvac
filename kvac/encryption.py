from __future__ import annotations
from typing import NamedTuple

from poksho.group.ristretto import RistrettoPoint, RistrettoScalar

from kvac.ristretto_sho import RistrettoSho
from kvac.exceptions import ZkGroupVerificationFailure, DeserializationFailure


class EncryptionParams(NamedTuple):
    """
    This class represents the system parameters for the encryption scheme.
    It includes RistrettoPoints G_1 and G_2.
    """
    G_1: RistrettoPoint
    G_2: RistrettoPoint

    @classmethod
    def generate(
            cls,
            system_label: bytes
    ) -> EncryptionParams:
        """
        Note that in order to generate new system parameters you need to provide a customization
        label that will be used for the RistrettoSho object to derive G_1 and G_2.
        :param system_label: bytes representation of a label for our system that is used as input
        for creating system params.
        :return: SystemParams with G_1 and G_2
        """
        sho = RistrettoSho(b'kvac.generic_encryption.SystemParams.generate', system_label)
        G_1 = sho.get_point()
        G_2 = sho.get_point()
        return cls(G_1, G_2)

    def __bytes__(self) -> bytes:
        return bytes(self.G_1.compress()) + bytes(self.G_2.compress())

    @classmethod
    def from_bytes(cls, system_params_bytes: bytes) -> EncryptionParams:
        if len(system_params_bytes) != 64:
            raise DeserializationFailure('Provided input was not 64 bytes.')
        G_1 = RistrettoPoint.decompress_bytes(bytes(system_params_bytes[0:32]))
        G_2 = RistrettoPoint.decompress_bytes(bytes(system_params_bytes[32:64]))
        return cls(G_1, G_2)

    def __eq__(self, other) -> bool:
        if not isinstance(other, EncryptionParams):
            return False
        return self.G_1 == other.G_1 and self.G_2 == other.G_2


class KeyPair(NamedTuple):
    """
    This class represents a key pair for encryption. It includes the private parameters
    RistrettoScalars a1 and a2, the public parameter RistrettoPoint A, and a bytes
    representation of a label that is used to instantiate RistrettoSho objects for hashing into G.
    For a high-level intuition see "The Signal Private Group System and Anonymous Credentials
    Supporting Verifiable Encryption" (Chase et al., 2020).
    This implementation is similar to uid encryption of Signals implementation. It can only encrypt
    messages of size 16 bytes, since encoding to G only works on 16 bytes.
    Reference:
    https://github.com/signalapp/libsignal/blob/main/rust/zkgroup/src/crypto/uid_encryption.rs
    """

    a: PrivateKey
    A: PublicKey

    @classmethod
    def derive_from(
            cls,
            system: EncryptionParams,
            master_key: bytes,
    ) -> KeyPair:
        """
        This function derives the secret params a1 and a2 from a master key. Furthermore, it
        calculates the public parameter A. It also stores the customization label that will be
        used for RistrettoSho objects to hash to G.

        """
        private_sho = RistrettoSho(b'kvac.generic_encryption.KeyPair.derive_from', master_key)
        a1 = private_sho.get_scalar()
        a2 = private_sho.get_scalar()
        a = PrivateKey(a1, a2)
        A = PublicKey(system.G_1 ** a1 * system.G_2 ** a2, system.G_1, system.G_2)
        return cls(a, A)

    def encrypt(
            self,
            m: bytes
    ) -> Ciphertext:
        """
        Decryption of a message in bytes representation
        :param m: Plaintext m
        :return: Ciphertext
        """
        if len(m) != 16:
            raise ValueError('Only messages of 16 bytes are supported.')
        # M1 = HashToG(m)
        M1 = hash_to_G(m)
        # M2 = EncodeToG(m)
        M2 = encode_to_G(m)
        # E_1 = M1 ^ a_1
        E_1 = M1 ** self.a.scalar1
        # E_2 = ((E_1) ^ a_2) * M2
        E_2 = (E_1 ** self.a.scalar2) * M2
        return Ciphertext(E_1, E_2)

    def decrypt(
            self,
            ciphertext: Ciphertext
    ) -> bytes:
        """
        Decryption of a ciphertext.
        :param ciphertext: Ciphertext
        :return: Plaintext m
        """
        # E_1 != 1 ?
        if ciphertext.E_1 == RistrettoPoint.identity():
            raise ZkGroupVerificationFailure()

        # M2' = E_2 / ((E_1) ^ a_2)
        decrypted_M2 = ciphertext.E_2 / (ciphertext.E_1 ** self.a.scalar2)
        # m' = DecodeFromG(M2')
        decrypted_m = decrypted_M2.to_bytes()
        # M1' = HashToG(m')
        decrypted_M1 = hash_to_G(decrypted_m)

        # E_1 = M1' ^ a_1 ?
        if ciphertext.E_1 == decrypted_M1 ** self.a.scalar1:
            return decrypted_m
        raise ZkGroupVerificationFailure()

    def __eq__(self, other) -> bool:
        if not isinstance(other, KeyPair):
            return False
        return self.a == other.a and self.A == other.A

    def __bytes__(self) -> bytes:
        return bytes(self.a) + bytes(self.A)

    @classmethod
    def from_bytes(cls, key_pair_bytes: bytes) -> KeyPair:
        if len(key_pair_bytes) != 160:
            raise DeserializationFailure('Provided input was not 160 bytes.')
        a1 = RistrettoScalar.from_bytes(bytes(key_pair_bytes[0:32]))
        a2 = RistrettoScalar.from_bytes(bytes(key_pair_bytes[32:64]))
        public_key = RistrettoPoint.decompress_bytes(bytes(key_pair_bytes[64:96]))
        G_1 = RistrettoPoint.decompress_bytes(bytes(key_pair_bytes[96:128]))
        G_2 = RistrettoPoint.decompress_bytes(bytes(key_pair_bytes[128:160]))
        a = PrivateKey(a1, a2)
        A = PublicKey(public_key, G_1, G_2)
        return cls(a, A)


class Ciphertext(NamedTuple):
    """
    This class represents a ciphertext. It includes the RistrettoPoint E1 and RistrettoPoint E2,
    representing the two parts of the ciphertext.
    """
    E_1: RistrettoPoint
    E_2: RistrettoPoint

    def __bytes__(self) -> bytes:
        return bytes(self.E_1.compress()) + bytes(self.E_2.compress())

    @classmethod
    def from_bytes(cls, ciphertext_bytes: bytes) -> Ciphertext:
        if len(ciphertext_bytes) != 64:
            raise DeserializationFailure('Provided input was not 64 bytes.')
        E_1 = RistrettoPoint.decompress_bytes(bytes(ciphertext_bytes[0:32]))
        E_2 = RistrettoPoint.decompress_bytes(bytes(ciphertext_bytes[32:64]))
        return cls(E_1, E_2)

    def __eq__(self, other) -> bool:
        if not isinstance(other, Ciphertext):
            return False
        return self.E_1 == other.E_1 and self.E_2 == other.E_2


class PublicKey(NamedTuple):
    """Represents a public key."""

    key: RistrettoPoint  # key is the actual public key.
    base1: RistrettoPoint
    base2: RistrettoPoint

    def __bytes__(self) -> bytes:
        return bytes(self.key.compress())\
            + bytes(self.base1.compress())\
            + bytes(self.base2.compress())

    def __eq__(self, other) -> bool:
        if not isinstance(other, PublicKey):
            return False
        return self.key == other.key


class PrivateKey(NamedTuple):
    """Represents a private key."""

    scalar1: RistrettoScalar
    scalar2: RistrettoScalar

    def __bytes__(self) -> bytes:
        return bytes(self.scalar1)\
            + bytes(self.scalar2)

    def __eq__(self, other) -> bool:
        if not isinstance(other, PrivateKey):
            return False
        return self.scalar1 == other.scalar1 and self.scalar2 == other.scalar2


def hash_to_G(m: bytes) -> RistrettoPoint:
    sho = RistrettoSho(b'kvac.generic_encryption.KeyPair.hashing', m)
    M1 = sho.get_point()
    return M1


def encode_to_G(m: bytes) -> RistrettoPoint:
    M2 = RistrettoPoint.from_bytes(m)
    return M2
