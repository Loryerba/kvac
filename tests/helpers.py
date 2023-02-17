import secrets
import pytest

from kvac.kvac import KVAC, Attribute

from kvac.ristretto_sho import RistrettoSho
from kvac.system_params import SystemParams
from kvac.issuer_key import IssuerKeyPair
from kvac.verifiable_encryption import KeyPair as HidingKeyPair, \
    MessageToEncrypt as MessageToHide


# pytest fixtures constantly redefine outer names, so ignore the warning.
# pylint: disable=redefined-outer-name


@pytest.fixture
def sho():
    return RistrettoSho(b"test_kvac.sho", secrets.token_bytes(256))


@pytest.fixture
def attributes(sho):
    return {
        "a1": sho.get_point(),
        "a2": MessageToHide(sho.squeeze(16), sho.squeeze(7)),
        "a3": MessageToHide(sho.squeeze(16), sho.squeeze(13)),
        "a4": sho.get_point(),
    }


@pytest.fixture
def issuer_key():
    system = SystemParams.generate(
        6,  # We need 2 components for our two hidden attributes and one for the two revealed ones
        "test"
    )
    issuer_key = IssuerKeyPair.generate(system)
    return issuer_key


@pytest.fixture
def master_key():
    return b"hiding_master_key"


@pytest.fixture
def hiding_keys(issuer_key, master_key):
    encryption_params = issuer_key.public.system.G_es
    return [
        HidingKeyPair.derive_from(encryption_params[0], master_key, b"attribute_1"),
        HidingKeyPair.derive_from(encryption_params[1], master_key, b"attribute_2")
    ]


class ExampleCredential(KVAC):
    """A test credential with some blind and/or hidden and some revealed attributes."""

    a1 = Attribute()
    a2 = Attribute(hidden=True)
    a3 = Attribute(blind=True, hidden=True)
    a4 = Attribute(blind=True)


@pytest.fixture
def valid_credential(issuer_key, attributes):
    credential = ExampleCredential(issuer_key=issuer_key.public, **attributes)
    request, commitment = credential.request()
    response = ExampleCredential.issue(
        issuer_key=issuer_key, request=request, commitment=commitment
    )
    credential.obtain_tag(response=response)
    return credential
