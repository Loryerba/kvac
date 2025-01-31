from __future__ import annotations
import secrets
from typing import List, NamedTuple

from poksho.group.ristretto import RistrettoPoint, RistrettoScalar

from kvac.ristretto_sho import RistrettoSho
from kvac.system_params import SystemParams


class IssuerPublicKey(NamedTuple):
    """Represents the public key of an issuer.
    It also stores global system parameters."""
    C_W: RistrettoPoint
    I: RistrettoPoint
    system: SystemParams

    @property
    def max_attributes(self) -> int:
        return self.system.max_attributes


class IssuerSecretKey(NamedTuple):
    """Represents the private key of an issuer."""
    w: RistrettoScalar
    wprime: RistrettoScalar
    x0: RistrettoScalar
    x1: RistrettoScalar
    ys: List[RistrettoScalar]


class IssuerKeyPair(NamedTuple):
    """Represents an issuer's key pair."""

    secret: IssuerSecretKey
    public: IssuerPublicKey

    @classmethod
    def generate(
            cls,
            system: SystemParams,
            num_attributes: int,
    ) -> IssuerKeyPair:
        """Generates a new issuer key pair."""
        if num_attributes > system.max_attributes:
            raise ValueError(f'This system only supports credentials with up to {system.max_attributes} attributes')

        sho = RistrettoSho(
            b'kvac.issuer_key.IssuerKeyPair.generate',
            secrets.token_bytes(256)
        )

        # private values
        w = sho.get_scalar()
        wprime = sho.get_scalar()
        x0 = sho.get_scalar()
        x1 = sho.get_scalar()
        ys = [sho.get_scalar() for _ in range(num_attributes)]

        C_W = (system.G_w ** w) * (system.G_wprime ** wprime)
        I = system.G_V / ((system.G_x0 ** x0) * (system.G_x1 ** x1))
        for G_y, y in zip(system.G_ys, ys):
            I /= G_y ** y

        secret = IssuerSecretKey(w=w, wprime=wprime, x0=x0, x1=x1, ys=ys)
        public = IssuerPublicKey(C_W=C_W, I=I, system=system)
        return cls(secret=secret, public=public)

    @property
    def max_attributes(self) -> int:
        return self.public.max_attributes
