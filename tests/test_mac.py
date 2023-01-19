import pytest

import kvac


class TestMac:
    """
    MAC tests
    """
    @pytest.fixture
    def macer(self):
        sho = kvac.RistrettoSho(b'TestMac::macer', b'')
        system = kvac.SystemParams.generate(4, sho)
        key = kvac.IssuerKeyPair.generate(system, sho)
        return kvac.MAC(key)

    def test_mac_valid(self, macer):
        sho = kvac.RistrettoSho(b'test_mac_valid', b'')
        messages = [sho.get_point() for _ in range(4)]
        tag = macer.mac(messages, sho)
        assert macer.verify(messages, tag)

    def test_mac_invalid(self, macer):
        sho = kvac.RistrettoSho(b'test_mac_invalid', b'')
        messages = [sho.get_point() for _ in range(4)]
        tag = macer.mac(messages, sho)

        messages[0] = sho.get_point()
        assert not macer.verify(messages, tag)
