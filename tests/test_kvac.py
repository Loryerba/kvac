# pylint doesn't recognize the necessary pytest fixtures.
# pylint: disable-next=unused-import
from helpers import ExampleCredential, issuer_key, attributes, sho

from kvac.commitment import BlindAttributeCommitment


# pytest fixtures constantly redefine outer names, so ignore the warning.
# pylint: disable=redefined-outer-name


def test_kvac_complete_example(issuer_key, attributes):
    commitment = BlindAttributeCommitment.new(
        issuer_key.public, [attributes["a3"], attributes["a4"]]
    )

    # user
    request, user_key = ExampleCredential.request(
        issuer_key=issuer_key.public, **attributes
    )

    # issuer
    response = ExampleCredential.issue(
        issuer_key=issuer_key, request=request, commitment=commitment
    )

    # user
    _ = ExampleCredential(
        issuer_key=issuer_key.public,
        user_key=user_key,
        request=request,
        response=response,
    )


def test_kvac_attributes(issuer_key, attributes):
    commitment = BlindAttributeCommitment.new(
        issuer_key.public, [attributes["a3"], attributes["a4"]]
    )
    request, user_key = ExampleCredential.request(
        issuer_key=issuer_key.public, **attributes
    )
    response = ExampleCredential.issue(
        issuer_key=issuer_key, request=request, commitment=commitment
    )
    cred = ExampleCredential(
        issuer_key=issuer_key.public,
        user_key=user_key,
        request=request,
        response=response,
    )

    assert cred.a1 == attributes["a1"]
    assert cred.a2 == attributes["a2"]
    assert cred.a3 == attributes["a3"]
    assert cred.a4 == attributes["a4"]
