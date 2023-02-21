import secrets
import pytest

import kvac
from kvac import elgamal


# pytest fixtures constantly redefine outer names, so ignore the warning.
# pylint: disable=redefined-outer-name


@pytest.fixture
def number_of_attributes():
    return 4


@pytest.fixture
def mac(number_of_attributes):
    system = kvac.SystemParams.generate(number_of_attributes, "test")
    key = kvac.IssuerKeyPair.generate(system, number_of_attributes)
    return kvac.MAC(key)


@pytest.fixture
def attributes(number_of_attributes, sho):
    return [sho.get_point() for _ in range(number_of_attributes)]


@pytest.fixture
def sho():
    return kvac.RistrettoSho(b"test", secrets.token_bytes(256))


class TestMac:
    """MAC tests."""

    def test_mac_valid(self, mac, attributes):
        tag = mac.mac(attributes)
        assert mac.verify(attributes, tag) is True

    def test_mac_invalid(self, mac, attributes, sho):
        tag = mac.mac(attributes)
        attributes[0] = sho.get_point()
        assert mac.verify(attributes, tag) is False


class TestBlindMAC:
    """Blind MAC tests. In this case, some attributes are blinded so the issuer
    does not see them."""

    def test_mac_valid_all_blind(self, mac, attributes):
        key = elgamal.ElGamalKeyPair.generate(mac.key.public.system.G)
        blinded = [key.encrypt(a) for a in attributes]
        encrypted_tag = mac.blind_mac(key.public, [], blinded)
        tag = encrypted_tag.decrypt(key)
        assert mac.verify(attributes, tag) is True

    def test_mac_valid_some_blind(self, mac, attributes):
        key = elgamal.ElGamalKeyPair.generate(mac.key.public.system.G)
        clear = attributes[: len(attributes) // 2]
        blinded = [key.encrypt(a) for a in attributes[len(attributes) // 2 :]]
        encrypted_tag = mac.blind_mac(key.public, clear, blinded)
        tag = encrypted_tag.decrypt(key)
        assert mac.verify(attributes, tag) is True

    def test_mac_valid_none_blind(self, mac, attributes):
        key = elgamal.ElGamalKeyPair.generate(mac.key.public.system.G)
        encrypted_tag = mac.blind_mac(key.public, attributes, [])
        tag = encrypted_tag.decrypt(key)
        assert mac.verify(attributes, tag) is True

    def test_mac_invalid(self, mac, attributes, sho):
        key = elgamal.ElGamalKeyPair.generate(mac.key.public.system.G)
        blinded = [key.encrypt(a) for a in attributes]
        encrypted_tag = mac.blind_mac(key.public, [], blinded)
        tag = encrypted_tag.decrypt(key)
        attributes[0] = sho.get_point()
        assert mac.verify(attributes, tag) is False
