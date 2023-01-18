import kvac


def test_version():
    print(kvac.__version__)


class TestImports:
    def test_imports_sho(self):
        from poksho.poksho import SHO

    def test_imports_curve(self):
        from curve25519_dalek.ristretto import RistrettoPoint, CompressedRistretto
        from curve25519_dalek.scalar import Scalar
