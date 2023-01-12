from typing import List, NamedTuple

from curve25519_dalek.ristretto import RistrettoPoint
from curve25519_dalek.scalar import Scalar

from .ristretto_sho import RistrettoSho
from .issuer_key_pair import IssuerKeyPair


MAX_MESSAGES = 4


class AlgebraicMACTag(NamedTuple):
    """
    Represents an Algebraic MAC Tag.
    """
    t: Scalar
    U: RistrettoPoint
    V: RistrettoPoint


class AlgebraicMAC(NamedTuple):
    """
    Must be initialized with a ServerKeyPair.
    Can be used to create or verify Algebraic MACs:
        - to create a MAC, call `mac` with a list of messages
          and a `RistrettoSho` instance
        - to verify a MAC, call `verify` with a list of messages and the tag
    """

    key: IssuerKeyPair

    def mac(
            self,
            messages: List[RistrettoPoint],
            sho: RistrettoSho,
    ) -> AlgebraicMACTag:
        if len(messages) > self.key.max_messages:
            raise ValueError(
                f'Too many messages: {len(messages)}, maximum is {self.key.max_messages}'
            )

        t = sho.get_scalar()
        U = sho.get_point()

        V = self.key.W + U * (self.key.x0 + self.key.x1 * t)
        for Mn, yn in zip(messages, self.key.ys):
            V += Mn * yn

        return AlgebraicMACTag(t, U, V)

    def verify(
            self,
            messages: List[RistrettoPoint],
            tag: AlgebraicMACTag,
    ) -> bool:
        if len(messages) > self.key.max_messages:
            raise ValueError(
                f'Too many messages: {len(messages)}, maximum is {self.key.max_messages}'
            )

        V = self.key.W + tag.U * (self.key.x0 + self.key.x1 * tag.t)
        for Mn, yn in zip(messages, self.key.ys):
            V += Mn * yn

        return tag.V == V
