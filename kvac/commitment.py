"""
This module implements the commitment scheme that is used to commit to multiple
attributes. The commitment is created by the user and then transmitted to the
issuer. The issuer can then use it to verify that blinded values during the
credential issuance request match the commitment.

THIS COMMITMENT SCHEME IS DETERMINISTIC AND THEREFORE RELIES ON HIGH ENTROPY
IN AT LEAST ONE ATTRIBUTE TO HIDE THE VALUES COMMITTED TO!

It is deterministic so that the
server can verify that a user knows the committed to values for a stored commitment.
"""

from __future__ import annotations
from typing import List, NamedTuple

from curve25519_dalek.ristretto import RistrettoPoint
from curve25519_dalek.scalar import Scalar as RistrettoScalar

from kvac.ristretto_sho import RistrettoSho
from kvac.system_params import SystemParams


class BlindAttributeCommitment(NamedTuple):
    """Represents a commitment on some attributes.
    This is used to commit to blind values when issuing a KVAC on blind attributes."""

    Js: List[RistrettoPoint]
    Jr: RistrettoPoint

    @classmethod
    def new(
        cls,
        params: SystemParams,
        attributes: List[RistrettoPoint],
    ) -> BlindAttributeCommitment:
        return BlindAttributeCommitmentWithSecretNonce.new(params, attributes).C


class BlindAttributeCommitmentWithSecretNonce(NamedTuple):
    """Represents a Commitment with a secret nonce."""

    C: BlindAttributeCommitment
    j_r: RistrettoScalar

    @staticmethod
    def derive_jr(attributes: List[RistrettoPoint]) -> RistrettoScalar:
        """Deterministically derives a scalar from a list of attributes."""
        sho = RistrettoSho(b"kvac.commitment.derive_jr", b"")
        for attribute in attributes:
            sho.absorb_and_ratchet(bytes(attribute.compress()))
        return sho.get_scalar()

    @classmethod
    def new(
        cls,
        params: SystemParams,
        attributes: List[RistrettoPoint],
    ) -> BlindAttributeCommitmentWithSecretNonce:
        """Create a new commitment to the given attributes."""

        if len(attributes) > params.max_attributes:
            raise ValueError(
                f"Too many attributes: {len(attributes)}, max: {len(params.G_js)}"
            )

        j_r = cls.derive_jr(attributes)

        return cls(
            C=BlindAttributeCommitment(
                Js=[
                    G_j * j_r + attribute
                    for G_j, attribute in zip(params.G_js, attributes)
                ],
                Jr=params.G_r * j_r,
            ),
            j_r=j_r,
        )
