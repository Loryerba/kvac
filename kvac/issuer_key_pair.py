from typing import List, NamedTuple
from curve25519_dalek.ristretto import RistrettoPoint
from curve25519_dalek.scalar import Scalar

from .ristretto_sho import RistrettoSho
from .system_params import SystemParams


class IssuerPublicKey(NamedTuple):
    C_w: RistrettoPoint
    I: RistrettoPoint


class IssuerKeyPair(NamedTuple):
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
    def generate(
            cls,
            system: SystemParams,
            sho: RistrettoSho
    ) -> 'IssuerKeyPair':

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

        return cls(w, wprime, W, x0, x1, ys, C_w, I)

    def get_public_key(self) -> IssuerPublicKey:
        return IssuerPublicKey(self.C_w, self.I)
