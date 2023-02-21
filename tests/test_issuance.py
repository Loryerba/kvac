import pytest

# pylint doesn't recognize the necessary pytest fixtures.
# pylint: disable-next=unused-import
from helpers import ExampleCredential, issuer_key, attributes, sho

from kvac.kvac import IssuanceResponse
from kvac.mac import MAC


# pytest fixtures constantly redefine outer names, so ignore the warning.
# pylint: disable=redefined-outer-name


class TestIssuanceRequest:
    """Tests for the issuance request."""

    def test_attribute_definitions(self):
        assert len(ExampleCredential.attributes()) == 4

    def test_arguments_list_lengths(self, issuer_key, attributes):
        credential = ExampleCredential(
            issuer_key=issuer_key.public, **attributes
        )

        request, _ = credential.request()

        # We only have two attributes each, but both one blind and one unblind attribute
        # consists of two components because they need to be hidden during presentation.
        assert len(request.clear_attributes) == 3
        assert len(request.blinded_attributes) == 3

    def test_arguments_in_right_list(self, issuer_key, attributes):
        credential = ExampleCredential(
            issuer_key=issuer_key.public, **attributes
        )
        request, _ = credential.request()

        for a in credential.clear_attribute_components():
            assert a in request.clear_attributes
            assert a not in [
                credential.user_key.decrypt(c) for c in request.blinded_attributes
            ]
        for a in credential.blind_attribute_components():
            assert a not in request.clear_attributes
            assert a in [
                credential.user_key.decrypt(c) for c in request.blinded_attributes
            ]

    def test_valid(self, issuer_key, attributes):
        credential = ExampleCredential(
            issuer_key=issuer_key.public, **attributes
        )
        request, _ = credential.request()

        assert request.verify(issuer_key.public, credential.user_key.public) is True

    def test_invalid(self, issuer_key, attributes, sho):
        credential = ExampleCredential(
            issuer_key=issuer_key.public, **attributes
        )
        request, _ = credential.request()

        request.blinded_attributes[0] = credential.user_key.encrypt(sho.get_point())

        assert request.verify(issuer_key.public, credential.user_key.public) is False


class TestIssuanceResponse:
    """Tests for the issuance response."""

    def test_valid(self, issuer_key, attributes):
        credential = ExampleCredential(
            issuer_key=issuer_key.public, **attributes
        )
        request, commitment = credential.request()
        response = ExampleCredential.issue(
            issuer_key=issuer_key,
            request=request,
            commitment=commitment,
        )
        assert response.verify(issuer_key.public, request) is True

    def test_invalid(self, issuer_key, attributes, sho):
        credential = ExampleCredential(
            issuer_key=issuer_key.public, **attributes
        )
        request, commitment = credential.request()
        response = ExampleCredential.issue(
            issuer_key=issuer_key,
            request=request,
            commitment=commitment,
        )
        request.clear_attributes[0] = sho.get_point()
        assert response.verify(issuer_key.public, request) is False

    def test_commitment_missmatch(self, issuer_key, attributes, sho):
        credential = ExampleCredential(
            issuer_key=issuer_key.public, **attributes
        )
        request, commitment = credential.request()

        commitment.Js[0] = sho.get_point()

        with pytest.raises(Exception):
            ExampleCredential.issue(
                issuer_key=issuer_key,
                request=request,
                commitment=commitment,
            )

    def test_tag_valid(self, issuer_key, attributes):
        credential = ExampleCredential(
            issuer_key=issuer_key.public, **attributes
        )
        request, _ = credential.request()
        response = IssuanceResponse.new(issuer_key, request)
        tag = response.tag.decrypt(credential.user_key)
        mac = MAC(issuer_key)
        assert mac.verify(
            credential.clear_attribute_components() + credential.blind_attribute_components(),
            tag
        ) is True
