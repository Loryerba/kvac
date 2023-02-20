import pytest

# pylint doesn't recognize the necessary pytest fixtures.
# pylint: disable-next=unused-import
from common import ExampleCredential, issuer_key, attributes, sho, hiding_keys, master_key, credential_full_example
from kvac.exceptions import CallNotAllowed
from kvac.kvac import KVAC, Attribute

from kvac.issuer_key import IssuerKeyPair


# pytest fixtures constantly redefine outer names, so ignore the warning.
# pylint: disable=redefined-outer-name


def test_kvac_complete_example(issuer_key, attributes, hiding_keys):
    credential_full_example(ExampleCredential, issuer_key, attributes, hiding_keys)


def test_cannot_activate_before_requesting_credential(issuer_key, attributes):
    credential = ExampleCredential(
        issuer_key=issuer_key.public, **attributes
    )
    with pytest.raises(CallNotAllowed):
        credential.activate(response=None)  # type: ignore


def test_cannot_present_kvac_before_having_obtained_tag(issuer_key, attributes):
    credential = ExampleCredential(
        issuer_key=issuer_key.public, **attributes
    )
    credential.request()
    with pytest.raises(CallNotAllowed):
        credential.present(hiding_keys=[])


class TestAttributes:
    """Tests for scalar attributes in credentials."""

    def test_kvac_attributes(self, issuer_key, attributes, hiding_keys):
        credential = credential_full_example(ExampleCredential, issuer_key, attributes, hiding_keys)

        assert credential.a1 == attributes["a1"]
        assert credential.a2 == attributes["a2"].message
        assert credential.a3 == attributes["a3"].message
        assert credential.a4 == attributes["a4"]


    def test_scalar_attributes(self, sho):
        class Credential(KVAC):
            """A test credential with scalar attributes."""
            a1 = Attribute()
            a2 = Attribute(scalar=True)
            a3 = Attribute(scalar=True, blind=True)

        system = Credential.generate_system("test_kvac.TestAttributes.test_scalar_attributes")
        issuer_key = IssuerKeyPair.generate(system)

        attributes = {
            "a1": sho.get_point(),
            "a2": sho.get_scalar(),
            "a3": sho.get_scalar(),
        }

        credential = credential_full_example(Credential, issuer_key, attributes, [])

        assert credential.a1 == attributes["a1"]
        assert credential.a2 == attributes["a2"]
        assert credential.a3 == attributes["a3"]
