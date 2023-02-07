import secrets
import pytest

from kvac.kvac import KVAC, Attribute

from kvac.ristretto_sho import RistrettoSho
from kvac.system_params import SystemParams
from kvac.issuer_key import IssuerKeyPair


# pytest fixtures constantly redefine outer names, so ignore the warning.
# pylint: disable=redefined-outer-name


@pytest.fixture
def sho():
    return RistrettoSho(b"test_kvac.sho", secrets.token_bytes(256))


@pytest.fixture
def attributes(sho):
    return {
        "a1": sho.get_point(),
        "a2": sho.get_point(),
        "a3": sho.get_point(),
        "a4": sho.get_point(),
    }


@pytest.fixture
def issuer_key():
    system = SystemParams.generate(4, "test")
    issuer_key = IssuerKeyPair.generate(system)
    return issuer_key


class ExampleCredential(KVAC):
    """A test credential with some blind and some non-blind attributes."""

    a1 = Attribute()
    a2 = Attribute()
    a3 = Attribute(blind=True)
    a4 = Attribute(blind=True)
