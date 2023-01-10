from typing import Tuple, NamedTuple
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

    G_y1: RistrettoPoint
    G_y2: RistrettoPoint
    G_y3: RistrettoPoint
    G_y4: RistrettoPoint

    G_m1: RistrettoPoint
    G_m2: RistrettoPoint
    G_m3: RistrettoPoint
    G_m4: RistrettoPoint

    G_V: RistrettoPoint

    # not mentioned in the paper, but used in the reference implementation
    G_z: RistrettoPoint  # used to prove a commitment on z

    @classmethod
    def generate(cls):
        sho = RistrettoSho(
            b'Signal_HPICrypto_SecMes2223_KVAC_Credential_SystemParams_Generation',
            b''
        )

        # this returns a SystemParams object
        # where all fields are randomly generated via sho.get_point()
        return cls(*[sho.get_point() for _ in range(len(cls._fields))])


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

    y1: Scalar
    y2: Scalar
    y3: Scalar
    y4: Scalar

    # public
    C_w: RistrettoPoint
    I: RistrettoPoint

    @classmethod
    def generate(cls, system: SystemParams, sho: RistrettoSho = None):
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

        y1 = sho.get_scalar()
        y2 = sho.get_scalar()
        y3 = sho.get_scalar()
        y4 = sho.get_scalar()

        # public
        C_w = W + (system.G_wprime * wprime)
        I = system.G_V \
            - (system.G_x0 * x0) \
            - (system.G_x1 * x1) \
            - (system.G_y1 * y1) \
            - (system.G_y2 * y2) \
            - (system.G_y3 * y3) \
            - (system.G_y4 * y4)
        # pylint: enable=invalid-name

        return cls(w, wprime, W, x0, x1, y1, y2, y3, y4, C_w, I)

    def get_public_key(self) -> Tuple[RistrettoPoint, RistrettoPoint]:
        return self.C_w, self.I
