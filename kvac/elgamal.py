"""
This module implements the ElGamal encryption scheme.
"""


from __future__ import annotations
from typing import NamedTuple
import secrets

from curve25519_dalek.ristretto import RistrettoPoint
from curve25519_dalek.scalar import Scalar as RistrettoScalar
from kvac.ristretto_sho import RistrettoSho


class ElGamalCiphertext(NamedTuple):
    """Represents an ElGamal ciphertext."""

    c1: RistrettoPoint
    c2: RistrettoPoint


class ElGamalCiphertextWithSecretNonce(NamedTuple):
    """Represents an ElGamal ciphertext including the secret nonce r that was
    used for encryption (base**r, message * public_key**r).
    """

    ciphertext: ElGamalCiphertext
    r: RistrettoScalar


class ElGamalPublicKey(NamedTuple):
    """Represents an ElGamal public key."""

    key: RistrettoPoint  # key is the actual public key.
    base: RistrettoPoint

    def encrypt(self, message: RistrettoPoint) -> ElGamalCiphertext:
        """Encrypts a message using this key."""
        c = self.encrypt_and_return_secret_nonce(message)
        return c.ciphertext

    def encrypt_and_return_secret_nonce(
        self, message: RistrettoPoint
    ) -> ElGamalCiphertextWithSecretNonce:
        """Encrypts a message using this key
        and also returns the secret nonce used for encryption."""
        sho = RistrettoSho(
            b"kvac.elgamal.ElGamalPublicKey.encrypt_and_return_secret_nonce",
            secrets.token_bytes(256),
        )
        r = sho.get_scalar()
        c1 = self.base * r
        c2 = message + (self.key * r)
        return ElGamalCiphertextWithSecretNonce(
            ciphertext=ElGamalCiphertext(c1=c1, c2=c2), r=r
        )


class ElGamalKeyPair(NamedTuple):
    """Represents a key pair for ElGamal encryption."""

    secret: RistrettoScalar
    public: ElGamalPublicKey

    @classmethod
    def generate(cls, base: RistrettoPoint) -> ElGamalKeyPair:
        """Generates a new ElGamal key pair."""
        sho = RistrettoSho(
            b"kvac.elgamal.ElGamalKeyPair.generate", secrets.token_bytes(256)
        )
        secret = sho.get_scalar()
        public = ElGamalPublicKey(key=base * secret, base=base)
        return cls(secret=secret, public=public)

    def decrypt(self, ciphertext: ElGamalCiphertext) -> RistrettoPoint:
        """Decrypts a single ciphertext."""
        return ciphertext.c2 - (ciphertext.c1 * self.secret)

    def encrypt(self, message: RistrettoPoint) -> ElGamalCiphertext:
        """Encrypts a message using this key pair."""
        return self.public.encrypt(message)
