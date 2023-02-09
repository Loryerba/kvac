from __future__ import annotations
from typing import NamedTuple

from poksho.group.ristretto import RistrettoPoint, RistrettoScalar

# from curve25519_dalek.ristretto import CompressedRistretto
# from curve25519_dalek.constants import RISTRETTO_BASEPOINT_POINT

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

    # def __bytes__(self) -> bytes:
    #    return bytes(self.G_1.compress()) + bytes(self.G_2.compress())

    # @classmethod
    # def from_bytes(cls, system_params_bytes: bytes) -> EncryptionParams:
    #    if len(system_params_bytes) != 64:
    #        raise DeserializationFailure('Provided input was not 64 bytes.')
    #    G_1 = CompressedRistretto(bytes(system_params_bytes[0:32])).decompress()
    #    G_2 = CompressedRistretto(bytes(system_params_bytes[32:64])).decompress()
    #    return cls(G_1, G_2)

    def __eq__(self, other) -> bool:
        if not isinstance(other, EncryptionParams):
            return False
        return self.G_1 == other.G_1 and self.G_2 == other.G_2


class KeyPair(NamedTuple):
    """
    This class represents a key pair for encryption. It includes the private parameters RistrettoScalars
    a1 and a2, the public parameter RistrettoPoint A, and a bytes representation of a label that
    is used to instantiate RistrettoSho objects for hashing into G.
    For a high-level intuition see "The Signal Private Group System and Anonymous Credentials
    Supporting Verifiable Encryption" (Chase et al., 2020).
    This implementation is similar to uid encryption of Signals implementation. It can only encrypt
    messages of size 16 bytes, since encoding to G only works on 16 bytes.
    Reference:
    https://github.com/signalapp/libsignal/blob/main/rust/zkgroup/src/crypto/uid_encryption.rs
    """

    a1: RistrettoScalar
    a2: RistrettoScalar
    A: RistrettoPoint

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
        A = system.G_1 ** a1 * system.G_2 ** a2
        return cls(a1, a2, A)

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
            raise ValueError('Only messages of 16 byte are supported.')
        sho = RistrettoSho(b'kvac.generic_encryption.KeyPair.hashing', m)
        # M1 = HashToG(m)
        M1 = sho.get_point()
        # M2 = EncodeToG(m)
        M2 = RistrettoPoint.encode_16byte(m)
        # E_1 = M1 ^ a_1
        E_1 = M1 ** self.a1
        # E_2 = ((E_1) ^ a_2) * M2
        E_2 = (E_1 ** self.a2) * M2
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
        if ciphertext.E_1 == RISTRETTO_BASEPOINT_POINT:
            raise ZkGroupVerificationFailure()

        # M2' = E_2 / ((E_1) ^ a_2)
        decrypted_M2 = ciphertext.E_2 / (ciphertext.E_1 ** self.a2)
        # m' = DecodeFromG(M2')
        decrypted_m = RistrettoPoint.decode_16byte(decrypted_M2)
        sho = RistrettoSho(b'kvac.generic_encryption.KeyPair.hashing', decrypted_m)
        # M1' = HashToG(m')
        decrypted_M1 = sho.get_point()

        # E_1 = M1' ^ a_1 ?
        if ciphertext.E_1 == decrypted_M1 ** self.a1:
            return decrypted_m
        raise ZkGroupVerificationFailure()

    def __eq__(self, other) -> bool:
        if not isinstance(other, KeyPair):
            return False
        return self.a1 == other.a1 and self.a2 == other.a2 and self.A == other.A

    # def __bytes__(self) -> bytes:
    #    return bytes(self.a1) + bytes(self.a2) + bytes(self.A.compress())

    # @classmethod
    # def from_bytes(cls, key_pair_bytes: bytes) -> KeyPair:
    #    if len(key_pair_bytes) != 96:
    #        raise DeserializationFailure('Provided input was not 96 bytes.')
    #    a1 = RistrettoScalar.from_bytes_mod_order(bytes(key_pair_bytes[0:32]))
    #    a2 = RistrettoScalar.from_bytes_mod_order(bytes(key_pair_bytes[32:64]))
    #    A = CompressedRistretto(bytes(key_pair_bytes[64:96])).decompress()
    #    return cls(a1, a2, A)


class Ciphertext(NamedTuple):
    """
    This class represents a ciphertext. It includes the RistrettoPoint E1 and RistrettoPoint E2,
    representing the two parts of the ciphertext.
    """
    E_1: RistrettoPoint
    E_2: RistrettoPoint

    #def __bytes__(self) -> bytes:
    #    return bytes(self.E_1.compress()) + bytes(self.E_2.compress())

    #@classmethod
    #def from_bytes(cls, ciphertext_bytes: bytes) -> Ciphertext:
    #    if len(ciphertext_bytes) != 64:
    #        raise DeserializationFailure('Provided input was not 64 bytes.')
    #    E_1 = CompressedRistretto(bytes(ciphertext_bytes[0:32])).decompress()
    #    E_2 = CompressedRistretto(bytes(ciphertext_bytes[32:64])).decompress()
    #    return cls(E_1, E_2)

    def __eq__(self, other) -> bool:
        if not isinstance(other, Ciphertext):
            return False
        return self.E_1 == other.E_1 and self.E_2 == other.E_2
