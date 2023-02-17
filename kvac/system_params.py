from __future__ import annotations
from typing import List, NamedTuple
from poksho.group.ristretto import RistrettoPoint

from kvac.verifiable_encryption import EncryptionParams
from kvac.ristretto_sho import RistrettoSho


class SystemParams(NamedTuple):
    """Encapsulates all public parameters of the system."""

    # documented in Signal's paper
    G_w: RistrettoPoint
    G_wprime: RistrettoPoint

    G_x0: RistrettoPoint
    G_x1: RistrettoPoint

    G_ys: List[RistrettoPoint]
    G_ms: List[RistrettoPoint]

    G_V: RistrettoPoint

    # not mentioned in the paper, but used in the reference implementation
    G_z: RistrettoPoint  # used to prove a commitment on z

    # Bases for commitments on blinded attributes in an issuance request.
    G_js: List[RistrettoPoint]
    G_r: RistrettoPoint

    # Used as a base for ElGamal encryption.
    G: RistrettoPoint

    # Separate encryption params for blinding of each attribute.
    G_es: List[EncryptionParams]

    @classmethod
    def generate(cls, max_attributes: int, label: str) -> SystemParams:
        """Generates system parameters. There is no randomness involved, only
        the label serves as a seed. The label should be a nothing-up-my-sleeve
        number.
        max_attributes is the maximum number of attributes the generated parameters
        will support."""

        # pylint: disable=too-many-locals
        sho = RistrettoSho(b"kvac.system_params.SystemParams.generate", label.encode())

        G_w, G_wprime, G_x0, G_x1, G_V, G_z = [sho.get_point() for _ in range(6)]
        G_ys = [sho.get_point() for _ in range(max_attributes)]
        G_ms = [sho.get_point() for _ in range(max_attributes)]
        G_js = [sho.get_point() for _ in range(max_attributes)]
        G_r = sho.get_point()
        G = sho.get_point()
        G_es = [
            EncryptionParams.generate(label.encode(), f"attribute_{i}".encode())
            # As every hidden attribute consists of two components, we need
            # at most one encryption params set for every two attributes.
            for i in range(max_attributes // 2)
        ]

        return cls(
            G_w=G_w,
            G_wprime=G_wprime,
            G_x0=G_x0,
            G_x1=G_x1,
            G_ys=G_ys,
            G_ms=G_ms,
            G_V=G_V,
            G_z=G_z,
            G_js=G_js,
            G_r=G_r,
            G=G,
            G_es=G_es
        )

    @property
    def max_attributes(self) -> int:
        return len(self.G_ys)
