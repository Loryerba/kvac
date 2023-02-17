import pytest

# pylint doesn't recognize the necessary pytest fixtures.
# pylint: disable-next=unused-import
from helpers import ExampleCredential, issuer_key, attributes, sho, hiding_keys, master_key
from kvac.exceptions import CallNotAllowed


# pytest fixtures constantly redefine outer names, so ignore the warning.
# pylint: disable=redefined-outer-name


def test_kvac_complete_example(issuer_key, attributes, hiding_keys):
    # user
    credential = ExampleCredential(
        issuer_key=issuer_key.public, **attributes
    )
    request, commitment = credential.request()

    # issuer
    response = ExampleCredential.issue(
        issuer_key=issuer_key, request=request, commitment=commitment
    )

    # user
    credential.obtain_tag(response=response)

    # user
    presentation = credential.present(
        issuer_key=issuer_key.public,
        hiding_keys=hiding_keys,
    )

    # issuer
    assert ExampleCredential.verify_present(
        issuer_key=issuer_key,
        presentation=presentation
    ) is True


def test_cannot_obtain_tag_before_requesting_credential(issuer_key, attributes):
    credential = ExampleCredential(
        issuer_key=issuer_key.public, **attributes
    )
    with pytest.raises(CallNotAllowed):
        credential.obtain_tag(response=None)  # type: ignore


def test_cannot_present_kvac_before_having_obtained_tag(issuer_key, attributes):
    credential = ExampleCredential(
        issuer_key=issuer_key.public, **attributes
    )
    credential.request()
    with pytest.raises(CallNotAllowed):
        credential.present(issuer_key=issuer_key, hiding_keys=[])


def test_kvac_attributes(issuer_key, attributes):
    credential = ExampleCredential(
        issuer_key=issuer_key.public, **attributes
    )
    request, commitment = credential.request()
    response = ExampleCredential.issue(
        issuer_key=issuer_key, request=request, commitment=commitment
    )
    credential.obtain_tag(response=response)

    assert credential.a1 == attributes["a1"]
    assert credential.a2 == attributes["a2"].message
    assert credential.a3 == attributes["a3"].message
    assert credential.a4 == attributes["a4"]
