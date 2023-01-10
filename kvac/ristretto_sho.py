from curve25519_dalek.ristretto import RistrettoPoint
from curve25519_dalek.scalar import Scalar

from poksho.poksho import SHO

"""
Reference: https://github.com/signalapp/libsignal/blob/main/rust/zkgroup/src/common/sho.rs
"""


class RistrettoSho:
    def __init__(self, customization_label: bytes, data: bytes = b''):
        # TODO: implement and use a HMAC-SHA-256 SHO
        self._sho = SHO(customization_label)
        self._sho.absorb_and_ratchet(data)

    def squeeze(self, out_length: int) -> bytes:
        return self._sho.squeeze_and_ratchet(out_length)

    def get_point(self) -> RistrettoPoint:
        point_bytes = self.squeeze(64)
        return RistrettoPoint.from_uniform_bytes(point_bytes)

    def get_point_single_elligator(self) -> RistrettoPoint:
        raise NotImplementedError("Single-elligator is not implemented")

    def get_scalar(self) -> Scalar:
        scalar_bytes = self.squeeze(64)
        return Scalar.from_bytes_mod_order_wide(scalar_bytes)
