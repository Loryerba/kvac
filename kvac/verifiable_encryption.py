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
            system_label: bytes,
            attribute_label: bytes,
    ) -> EncryptionParams:
        """
        Note that in order to generate new system parameters you need to provide a customization
        label that will be used for the RistrettoSho object to derive G_1 and G_2.
        :param system_label: bytes representation of a label for our system that is used as input
        for creating system params.
        :param attribute_label: bytes representation of a label that represents a credential attribute
        the encryption params are for
        :return: SystemParams with G_1 and G_2
        """
        sho = RistrettoSho(
            b'kvac.encryption.EncryptionParams.generate',
            system_label + attribute_label
        )
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


class KeyCommitment(NamedTuple):
    """
    This class represents a encryption key commitment.
    It includes the public parameter RistrettoPoint A.
    """

    A: RistrettoPoint

    def __bytes__(self) -> bytes:
        return bytes(self.A.compress())


class SecretKey(NamedTuple):
    """
    This class represents a secret key for encryption.
    It includes the private parameters RistrettoScalars a1 and a2.
    """
    a_1: RistrettoScalar
    a_2: RistrettoScalar

    def encrypt(
            self,
            attribute: AttributeRepresentationForEncryption
    ) -> Ciphertext:
        """
        Encryption of a message to a attribute representation using this key.
        """

        E_1 = attribute.M_1 ** self.a_1
        E_2 = (E_1 ** self.a_2) * attribute.M_2
        return Ciphertext(E_1=E_1, E_2=E_2)

    def decrypt(
            self,
            ciphertext: Ciphertext,
            hash_supplement: bytes
    ) -> AttributeRepresentationForEncryption:
        """
        Decryption of a ciphertext to a message using this key.
        Requires the hash_supplement used for obtaining the attribute representation as an extra argument
        as we cannot include it in the ciphertext without potentially leaking unwanted information.
        """
        decrypted_M2 = ciphertext.E_2 / (ciphertext.E_1 ** self.a_2)

        representation = AttributeRepresentationForEncryption.encode(
            MessageToEncrypt(message=decrypted_M2.to_bytes(), hash_supplement=hash_supplement)
        )
        if representation.M_1 ** self.a_1 != ciphertext.E_1:
            raise ZkGroupVerificationFailure()
        return representation

    def __bytes__(self) -> bytes:
        return bytes(self.a_1) + bytes(self.a_2)


class KeyPair(NamedTuple):
    """
    This class represents a key pair for encryption.
    For a high-level intuition see "The Signal Private Group System and Anonymous Credentials
    Supporting Verifiable Encryption" (Chase et al., 2020).
    This implementation is similar to uid encryption of Signals implementation. It can only encrypt
    messages of size 16 bytes, since encoding to G only works on 16 bytes.
    Reference:
    https://github.com/signalapp/libsignal/blob/main/rust/zkgroup/src/crypto/uid_encryption.rs
    """

    secret: SecretKey
    commitment: KeyCommitment

    @classmethod
    def derive_from(
            cls,
            system: EncryptionParams,
            attribute_label: bytes,
            master_key: bytes,
    ) -> KeyPair:
        """
        This function derives the secret params a1 and a2 for a attribute from a master key.
        Furthermore, it calculates the public parameter A.

        """
        private_sho = RistrettoSho(
            b'kvac.encryption.KeyPair.derive_from',
            attribute_label + master_key
        )
        a_1 = private_sho.get_scalar()
        a_2 = private_sho.get_scalar()
        A = system.G_1 ** a_1 * system.G_2 ** a_2
        return cls(secret=SecretKey(a_1=a_1, a_2=a_2), commitment=KeyCommitment(A=A))

    def __eq__(self, other) -> bool:
        if not isinstance(other, KeyPair):
            return False
        return self.secret == other.secret and self.commitment == other.commitment

    def __bytes__(self) -> bytes:
        return bytes(self.secret) + bytes(self.commitment)

    @classmethod
    def from_bytes(cls, key_pair_bytes: bytes) -> KeyPair:
        if len(key_pair_bytes) != 96:
            raise DeserializationFailure('Provided input was not 96 bytes.')
        a_1 = RistrettoScalar.from_bytes(bytes(key_pair_bytes[0:32]))
        a_2 = RistrettoScalar.from_bytes(bytes(key_pair_bytes[32:64]))
        A = RistrettoPoint.decompress_bytes(bytes(key_pair_bytes[64:96]))
        return cls(secret=SecretKey(a_1=a_1, a_2=a_2), commitment=KeyCommitment(A))

    def encrypt(
            self,
            attribute: AttributeRepresentationForEncryption
    ) -> Ciphertext:
        return self.secret.encrypt(attribute)

    def decrypt(
            self,
            ciphertext: Ciphertext,
            hash_supplement: bytes
    ) -> AttributeRepresentationForEncryption:
        return self.secret.decrypt(ciphertext, hash_supplement)


class MessageToEncrypt(NamedTuple):
    """
    This class represents a message to encrypt. Due to the specific way the encryption is performed,
    an additional byte string can be specified which is added to the message when hashing it.
    """
    message: bytes
    hash_supplement: bytes


class AttributeRepresentationForEncryption(NamedTuple):
    """
    This class holds a representation of an attribute byte string m as two Ristretto points in the format
    required for the encryption.
    It will compute M_1 as HashToG(m) and M_2 as EncodeToG(m).
    """

    hash_supplement: bytes
    M_1: RistrettoPoint
    M_2: RistrettoPoint

    @classmethod
    def encode(cls, m: MessageToEncrypt) -> AttributeRepresentationForEncryption:
        if len(m.message) != 16:
            raise ValueError('Only messages of 16 bytes are supported.')
        sho = RistrettoSho(b'kvac.encryption.AttributeEncodedForBlinding.encode', m.message + m.hash_supplement)
        M_1 = sho.get_point()
        M_2 = RistrettoPoint.from_bytes(m.message)

        return cls(hash_supplement=m.hash_supplement, M_1=M_1, M_2=M_2)

    def decode(self) -> bytes:
        """Extracts the original attribute byte representation while ensuring that both components actually
        belong to this attribute value."""
        m = self.M_2.to_bytes()
        if AttributeRepresentationForEncryption.encode(MessageToEncrypt(m, self.hash_supplement)).M_1 != self.M_1:
            raise ZkGroupVerificationFailure()
        return m

    def validate(self):
        self.decode()

    def __iter__(self):
        return iter([self.M_1, self.M_2])


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
