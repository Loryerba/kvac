"""
This module implements the algebraic MAC from
https://signal.org/blog/pdfs/signal_private_group_system.pdf.
"""

from typing import List, NamedTuple, Tuple
import secrets

from poksho.group.ristretto import RistrettoPoint, RistrettoScalar

from kvac.ristretto_sho import RistrettoSho
from kvac.issuer_key import IssuerKeyPair, IssuerPublicKey

from kvac.elgamal import ElGamalCiphertext, ElGamalKeyPair, ElGamalPublicKey


class TagCommitment(NamedTuple):
    """Represents a commitment for an Algebraic MAC tag."""

    Z: RistrettoPoint
    C_x0: RistrettoPoint
    C_x1: RistrettoPoint
    C_V: RistrettoPoint


class MACTag(NamedTuple):
    """Represents an Algebraic MAC tag."""

    t: RistrettoScalar
    U: RistrettoPoint
    V: RistrettoPoint

    def commit_and_return_secret_nonce(self, issuer_key: IssuerPublicKey) -> Tuple[TagCommitment, RistrettoScalar]:
        sho = RistrettoSho(
            b"kvac.mac.MACTag.commit_and_return_secret_nonce",
            secrets.token_bytes(256)
        )
        z = sho.get_scalar()

        Z = issuer_key.I ** z
        C_x0 = issuer_key.system.G_x0 ** z * self.U
        C_x1 = issuer_key.system.G_x1 ** z * self.U ** self.t
        C_V = issuer_key.system.G_V ** z * self.V

        return TagCommitment(Z=Z, C_x0=C_x0, C_x1=C_x1, C_V=C_V), z


class BlindMACTag(NamedTuple):
    """Represents an Algebraic MAC tag on blinded attributes."""

    t: RistrettoScalar
    U: RistrettoPoint
    S: ElGamalCiphertext  # encryption of V

    def decrypt(self, key: ElGamalKeyPair) -> MACTag:
        """Returns the MACTag. V is the decryption of S using the key."""
        return MACTag(t=self.t, U=self.U, V=key.decrypt(self.S))


class MAC:
    """An algebraic MAC algorithm. The algebraic structure of if allows
    zero-knowledge proofs on it. It also allows calculating a tag on blinded attributes."""

    def __init__(self, key: IssuerKeyPair):
        self.key = key

    def mac(
        self,
        attributes: List[RistrettoPoint],
    ) -> MACTag:
        """Calculate a tag for the attributes."""

        sho = RistrettoSho(b"kvac.mac.MAC.mac", secrets.token_bytes(256))
        t = sho.get_scalar()
        U = sho.get_point()
        V = self._calculate_V(t, U, attributes)
        return MACTag(t, U, V)

    def blind_mac_and_return_secret_nonce(
        self,
        user_key: ElGamalPublicKey,
        clear_attributes: List[RistrettoPoint],
        blinded_attributes: List[ElGamalCiphertext],
    ) -> Tuple[BlindMACTag, RistrettoScalar]:
        """Calculate a tag for the attributes. Attributes can be blinded by
        encrypting them with ElGamal encryption under the user_key.

        This version additionally returns the secret nonce used to encrypt part of the tag.
        """

        if self.key.max_attributes < len(clear_attributes) + len(blinded_attributes):
            raise ValueError(
                f"Too many attributes: {len(clear_attributes)=}, {len(blinded_attributes)=}, "
                + f"max_attributes={self.key.max_attributes}"
            )

        partial_tag = self.mac(clear_attributes)
        encrypted_partial_V = user_key.encrypt_and_return_secret_nonce(partial_tag.V)

        c1 = encrypted_partial_V.ciphertext.c1
        c2 = encrypted_partial_V.ciphertext.c2
        for attribute, y in zip(
            blinded_attributes, self.key.secret.ys[len(clear_attributes) :]
        ):
            c1 *= attribute.c1 ** y
            c2 *= attribute.c2 ** y

        return (
            BlindMACTag(
                t=partial_tag.t, U=partial_tag.U, S=ElGamalCiphertext(c1=c1, c2=c2)
            ),
            encrypted_partial_V.r,
        )

    def blind_mac(
        self,
        user_key: ElGamalPublicKey,
        clear_attributes: List[RistrettoPoint],
        blinded_attributes: List[ElGamalCiphertext],
    ) -> BlindMACTag:
        """Calculate a tag for the attributes. Attributes can be blinded by
        encrypting them with ElGamal encryption under the user_key."""

        tag, _ = self.blind_mac_and_return_secret_nonce(
            user_key, clear_attributes, blinded_attributes
        )
        return tag

    def verify(
        self,
        attributes: List[RistrettoPoint],
        tag: MACTag,
    ) -> bool:
        """Verifies that the given tag is valid for the given attributes."""
        return tag.V == self._calculate_V(tag.t, tag.U, attributes)

    def _calculate_V(
        self,
        t: RistrettoScalar,
        U: RistrettoPoint,
        attributes: List[RistrettoPoint],
    ) -> RistrettoPoint:
        """Deterministically calculates the V of a tag for a given t, U and attributes."""
        if len(attributes) > self.key.max_attributes:
            raise ValueError(
                f"Too many attributes: {len(attributes)}, maximum is {self.key.max_attributes}"
            )

        pk = self.key.public
        sk = self.key.secret

        V = pk.system.G_w ** sk.w * U ** (sk.x0 + sk.x1 * t)
        for Mn, yn in zip(attributes, sk.ys):
            V *= Mn ** yn

        return V
