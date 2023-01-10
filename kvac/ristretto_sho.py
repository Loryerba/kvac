from curve25519_dalek.ristretto import RistrettoPoint
from curve25519_dalek.scalar import Scalar

from poksho.poksho import SHO


class RistrettoSho:
    """
    Encapsulates SHO functions to provide convenient generation of Ristretto points and scalars.
    Reference: https://github.com/signalapp/libsignal/blob/main/rust/zkgroup/src/common/sho.rs
    """

    def __init__(self, customization_label: bytes, data: bytes):
        # TODO: implement and use a HMAC-SHA-256 SHO  # pylint: disable=fixme
        self._sho = SHO(customization_label)
        self._sho.absorb_and_ratchet(data)

    def squeeze(self, out_length: int) -> bytes:
        return self._sho.squeeze_and_ratchet(out_length)

    def get_point(self) -> RistrettoPoint:
        # point_bytes = self.squeeze(64)
        point_bytes = self.squeeze(16)
        # return RistrettoPoint.from_uniform_bytes(point_bytes)
        return RistrettoPoint.lizard_encode_sha256(point_bytes)

    def get_point_single_elligator(self) -> RistrettoPoint:
        raise NotImplementedError('Single-elligator is not implemented')

    def get_scalar(self) -> Scalar:
        # scalar_bytes = self.squeeze(64)
        scalar_bytes = self.squeeze(8)
        # return Scalar.from_bytes_mod_order_wide(scalar_bytes)
        return Scalar.from_u64(int.from_bytes(scalar_bytes, byteorder='big'))
