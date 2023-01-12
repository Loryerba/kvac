from typing import List, NamedTuple

from curve25519_dalek.ristretto import RistrettoPoint
from curve25519_dalek.scalar import Scalar

from .ristretto_sho import RistrettoSho
from .issuer_key_pair import IssuerKeyPair


MAX_MESSAGES = 4


class AlgebraicMAC(NamedTuple):
    """
    Represents an Algebraic MAC.
    """

    t: Scalar
    U: RistrettoPoint
    V: RistrettoPoint

    @classmethod
    def mac(
        cls,
        key: IssuerKeyPair,
        messages: List[RistrettoPoint],
        sho: RistrettoSho,
    ) -> 'AlgebraicMAC':
        if len(messages) > MAX_MESSAGES:
            raise ValueError(f'Too many messages: {len(messages)}, maximum is {MAX_MESSAGES}')

        t = sho.get_scalar()
        U = sho.get_point()

        V = key.W + U * (key.x0 + key.x1 * t)
        for Mn, yn in zip(messages, key.get_y()):
            V += Mn * yn

        return cls(t, U, V)

    def verify(self, key: IssuerKeyPair, messages: List[RistrettoPoint]) -> bool:
        if len(messages) > MAX_MESSAGES:
            raise ValueError(f'Too many messages: {len(messages)}, maximum is {MAX_MESSAGES}')

        V = key.W + self.U * (key.x0 + key.x1 * self.t)
        for Mn, yn in zip(messages, key.get_y()):
            V += Mn * yn

        return self.V == V
