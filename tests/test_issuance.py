import pytest

# pylint doesn't recognize the necessary pytest fixtures.
# pylint: disable-next=unused-import
from helpers import ExampleCredential, issuer_key, attributes, sho

from kvac.commitment import BlindAttributeCommitment
from kvac.kvac import IssuanceResponse
from kvac.mac import MAC


# pytest fixtures constantly redefine outer names, so ignore the warning.
# pylint: disable=redefined-outer-name


class TestIssuanceRequest:
    """Tests for the issuance request."""

    def test_attribute_definitions(self):
        assert len(ExampleCredential.attributes()) == 4

    def test_arguments_list_lengths(self, issuer_key, attributes):
        request, _ = ExampleCredential.request(
            issuer_key=issuer_key.public, **attributes
        )
        assert len(request.clear_attributes) == 2
        assert len(request.blinded_attributes) == 2

    def test_arguments_in_right_list(self, issuer_key, attributes):
        request, user_key = ExampleCredential.request(
            issuer_key=issuer_key.public, **attributes
        )

        # Credential.attributes is iterable
        # pylint: disable-next=not-an-iterable
        for a in ExampleCredential.attributes():
            if a.blind:
                assert attributes[a.name] not in request.clear_attributes
                assert attributes[a.name] in [
                    user_key.decrypt(c) for c in request.blinded_attributes
                ]
            else:
                assert attributes[a.name] in request.clear_attributes
                assert attributes[a.name] not in [
                    user_key.decrypt(c) for c in request.blinded_attributes
                ]

    def test_valid(self, issuer_key, attributes):
        request, user_key = ExampleCredential.request(
            issuer_key=issuer_key.public, **attributes
        )

        assert request.verify(issuer_key.public, user_key.public) is True

    def test_invalid(self, issuer_key, attributes, sho):
        request, user_key = ExampleCredential.request(
            issuer_key=issuer_key.public, **attributes
        )

        request.blinded_attributes[0] = user_key.encrypt(sho.get_point())

        assert request.verify(issuer_key.public, user_key.public) is False


class TestIssuanceResponse:
    """Tests for the issuance response."""

    def test_valid(self, issuer_key, attributes):
        commitment = BlindAttributeCommitment.new(
            issuer_key.public.system, [attributes['a3'], attributes['a4']]
        )
        request, _ = ExampleCredential.request(
            issuer_key=issuer_key.public, **attributes
        )
        response = ExampleCredential.issue(
            issuer_key=issuer_key,
            request=request,
            commitment=commitment,
        )
        assert response.verify(issuer_key.public, request) is True

    def test_invalid(self, issuer_key, attributes, sho):
        commitment = BlindAttributeCommitment.new(
            issuer_key.public.system, [attributes['a3'], attributes['a4']]
        )
        request, _ = ExampleCredential.request(
            issuer_key=issuer_key.public, **attributes
        )
        response = ExampleCredential.issue(
            issuer_key=issuer_key,
            request=request,
            commitment=commitment,
        )
        request.clear_attributes[0] = sho.get_point()
        assert response.verify(issuer_key.public, request) is False

    @pytest.mark.parametrize('commitment_attributes', [['a1'], ['a1', 'a2'], ['a1', 'a2', 'a3']])
    def test_commitment_missmatch(self, issuer_key, attributes, commitment_attributes):
        commitment = BlindAttributeCommitment.new(
            issuer_key.public.system, [attributes[a] for a in commitment_attributes]
        )
        request, _ = ExampleCredential.request(
            issuer_key=issuer_key.public, **attributes
        )

        with pytest.raises(Exception):
            ExampleCredential.issue(
                issuer_key=issuer_key,
                request=request,
                commitment=commitment,
            )

    def test_tag_valid(self, issuer_key, attributes):
        request, user_key = ExampleCredential.request(
            issuer_key=issuer_key.public, **attributes
        )
        response = IssuanceResponse.new(issuer_key, request)
        tag = response.tag.decrypt(user_key)
        mac = MAC(issuer_key)
        assert mac.verify(attributes.values(), tag) is True
