from curve25519_dalek.ristretto import RistrettoPoint
from curve25519_dalek.scalar import Scalar

from poksho import SHO
from poksho.group.ristretto import RistrettoPoint as GroupRistrettoPoint
from poksho.group.ristretto import RistrettoScalar as GroupRistrettoScalar


class RistrettoSho:
    """
    Encapsulates SHO functions to provide convenient generation of Ristretto points and scalars.
    Reference: https://github.com/signalapp/libsignal/blob/main/rust/zkgroup/src/common/sho.rs
    """

    def __init__(self, customization_label: bytes, data: bytes):
        self._sho = SHO(customization_label, use_hmac=True)
        self._sho.absorb_and_ratchet(data)

    def absorb(self, data: bytes):
        self._sho.absorb(data)

    def absorb_and_ratchet(self, data: bytes):
        self._sho.absorb_and_ratchet(data)

    def squeeze(self, out_length: int) -> bytes:
        return self._sho.squeeze_and_ratchet(out_length)

    def get_point(self) -> GroupRistrettoPoint:
        point_bytes = self.squeeze(64)
        return GroupRistrettoPoint(RistrettoPoint.from_uniform_bytes(point_bytes))

    def get_point_single_elligator(self) -> GroupRistrettoPoint:
        point_bytes = self.squeeze(32)
        return GroupRistrettoPoint(RistrettoPoint.from_uniform_bytes_single_elligator(point_bytes))

    def get_scalar(self) -> GroupRistrettoScalar:
        scalar_bytes = self.squeeze(64)
        return GroupRistrettoScalar(Scalar.from_bytes_mod_order_wide(scalar_bytes))
