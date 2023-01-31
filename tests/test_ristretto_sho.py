from curve25519_dalek.ristretto import CompressedRistretto
from curve25519_dalek.scalar import Scalar

from poksho.poksho.group.ristretto import RistrettoPoint as GroupRistrettoPoint
from poksho.poksho.group.ristretto import RistrettoScalar as GroupRistrettoScalar

from kvac import RistrettoSho


def test_ristretto_sho_get_point():
    sho = RistrettoSho(b"test", b"")
    assert sho.get_point() == GroupRistrettoPoint(CompressedRistretto(bytes([
        0x6c, 0x46, 0x32, 0xe5, 0x57, 0xc6, 0x22, 0xc2, 0x8f, 0xf4, 0x3e,
        0x67, 0xcf, 0xb5, 0x66, 0x9b, 0x3a, 0x24, 0xec, 0xff, 0x85, 0x56,
        0xa6, 0xfe, 0xed, 0xef, 0x85, 0x26, 0xcf, 0xc0, 0xd3, 0x17
    ])).decompress())


def test_ristretto_sho_get_point_single_elligator():
    sho = RistrettoSho(b"test", b"")
    assert sho.get_point_single_elligator() == GroupRistrettoPoint(CompressedRistretto(bytes([
        0x78, 0xe2, 0xe6, 0xb3, 0xa9, 0x8c, 0x82, 0xda, 0x9e, 0x70, 0x4c,
        0x7c, 0x15, 0xaa, 0xc4, 0xf9, 0xea, 0xd7, 0x6f, 0xcc, 0x90, 0x30,
        0x35, 0xb6, 0x48, 0x3d, 0xfe, 0xa0, 0x31, 0xe2, 0x19, 0x67
    ])).decompress())


def test_ristretto_sho_get_scalar():
    sho = RistrettoSho(b"test", b"")
    assert sho.get_scalar() == GroupRistrettoScalar(Scalar.from_bytes_mod_order(bytes([
        0x3f, 0x23, 0xf7, 0x10, 0x9c, 0x26, 0xeb, 0x6f, 0x6e, 0x17, 0xe4,
        0x92, 0x1b, 0x47, 0x41, 0xcf, 0x0f, 0xcd, 0xb7, 0x08, 0x58, 0xd2,
        0x76, 0xac, 0x6b, 0x19, 0xa3, 0xe1, 0x76, 0xac, 0xc7, 0x0d
    ])))
