from typing import List, NamedTuple
from curve25519_dalek.ristretto import RistrettoPoint

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
    def generate(
            cls,
            max_messages: int,
            sho: RistrettoSho
    ) -> 'SystemParams':

        G_w, G_wprime, G_x0, G_x1, G_V, G_z = [sho.get_point() for _ in range(6)]
        G_ys = [sho.get_point() for _ in range(max_messages)]
        G_ms = [sho.get_point() for _ in range(max_messages)]

        return cls(G_w, G_wprime, G_x0, G_x1, G_ys, G_ms, G_V, G_z)

    @classmethod
    def generate_signal_parameters(cls) -> 'SystemParams':
        sho = RistrettoSho(
            b'Signal_ZKGroup_20200424_Constant_Credentials_SystemParams_Generate',
            b''
        )
        G_w = sho.get_point()
        G_wprime = sho.get_point()

        G_x0 = sho.get_point()
        G_x1 = sho.get_point()

        G_ys = [sho.get_point() for _ in range(4)]
        G_ms = [sho.get_point() for _ in range(4)]

        G_V = sho.get_point()
        G_z = sho.get_point()

        G_ys.extend([sho.get_point() for _ in range(2)])
        G_ms.append(sho.get_point())

        return cls(G_w, G_wprime, G_x0, G_x1, G_ys, G_ms, G_V, G_z)

    @property
    def max_messages(self) -> int:
        return len(self.G_ys)
