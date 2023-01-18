from typing import List, NamedTuple, Optional, Tuple
from curve25519_dalek.ristretto import RistrettoPoint
from curve25519_dalek.scalar import Scalar

from .ristretto_sho import RistrettoSho


class SystemParams(NamedTuple):
    """
    Encapsulates all public parameters of the system.
    """

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

    @classmethod
    def generate(cls, max_messages: int) -> 'SystemParams':
        sho = RistrettoSho(
            b'Signal_HPICrypto_SecMes2223_KVAC_Credential_SystemParams_Generation',
            b''
        )

        G_w, G_wprime, G_x0, G_x1, G_V, G_z = [sho.get_point() for _ in range(6)]
        G_ys = [sho.get_point() for _ in range(max_messages)]
        G_ms = [sho.get_point() for _ in range(max_messages)]
        return cls(G_w, G_wprime, G_x0, G_x1, G_ys, G_ms, G_V, G_z)

    @property
    def max_messages(self) -> int:
        return len(self.G_ys)


class ServerKeyPair(NamedTuple):
    """
    Represents a Server's key pair, including private and public values.
    """

    # private
    w: Scalar
    wprime: Scalar
    W: RistrettoPoint

    x0: Scalar
    x1: Scalar

    ys: List[Scalar]

    # public
    C_w: RistrettoPoint
    I: RistrettoPoint

    @classmethod
    def generate(cls, system: SystemParams, sho: Optional[RistrettoSho] = None) -> 'ServerKeyPair':
        if sho is None:
            sho = RistrettoSho(
                b'Signal_HPICrypto_SecMes2223_KVAC_Credential_ServerKeyPair_Generation',
                b''
            )

        # pylint: disable=invalid-name
        # private
        w = sho.get_scalar()
        wprime = sho.get_scalar()
        W = system.G_w * w
        x0 = sho.get_scalar()
        x1 = sho.get_scalar()

        ys = [sho.get_scalar() for _ in range(system.max_messages)]

        # public
        C_w = W + (system.G_wprime * wprime)
        I = system.G_V - (system.G_x0 * x0) - (system.G_x1 * x1)
        for G_y, y in zip(system.G_ys, ys):
            I -= G_y * y
        # pylint: enable=invalid-name

        return cls(w, wprime, W, x0, x1, ys, C_w, I)

    def get_public_key(self) -> Tuple[RistrettoPoint, RistrettoPoint]:
        return self.C_w, self.I
