from typing import List, NamedTuple

from curve25519_dalek.ristretto import RistrettoPoint
from curve25519_dalek.scalar import Scalar

from .ristretto_sho import RistrettoSho
from .issuer_key_pair import IssuerKeyPair


class MACTag(NamedTuple):
    """
    Represents an Algebraic MAC Tag.
    """
    t: Scalar
    U: RistrettoPoint
    V: RistrettoPoint


class MAC:
    """
    Must be initialized with an IssuerKeyPair.
    Can be used to create or verify Algebraic MACs.
    """

    def __init__(self, key: IssuerKeyPair):
        self.key = key

    def mac(
            self,
            messages: List[RistrettoPoint],
            sho: RistrettoSho,
    ) -> MACTag:
        """
        :param messages: List of messages to be MAC'd
        :param sho: User-provided RistrettoSho for randomness.
                    Note that using a RistrettoSho with a known state will
                    produce the same MACs (when key and messages are also equal).
        :return: A MAC Tag on the messages using the stored IssuerKeyPair
        """
        t = sho.get_scalar()
        U = sho.get_point()
        V = self._calc_V(t, U, messages)

        return MACTag(t, U, V)

    def verify(
            self,
            messages: List[RistrettoPoint],
            tag: MACTag,
    ) -> bool:
        """
        :param messages: List of messages belonging to the MAC Tag
        :param tag: The MAC Tag to verify
        :return: Whether the MAC Tag is valid for the messages
        """
        return tag.V == self._calc_V(tag.t, tag.U, messages)

    # Helper methods
    def _calc_V(
            self,
            t: Scalar,
            U: RistrettoPoint,
            messages: List[RistrettoPoint],
    ) -> RistrettoPoint:
        """
        :param t: The t value of the MAC Tag
        :param U: The U value of the MAC Tag
        :param messages: List of messages belonging to the MAC Tag
        :return: The V value of the MAC Tag
        """
        if len(messages) > self.key.max_attributes:
            raise ValueError(
                f'Too many messages: {len(messages)}, maximum is {self.key.max_attributes}'
            )

        V = self.key.W + U * (self.key.x0 + self.key.x1 * t)
        for Mn, yn in zip(messages, self.key.ys):
            V += Mn * yn

        return V

    @property
    def max_attributes(self) -> int:
        return self.key.max_attributes
