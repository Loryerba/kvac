# pylint doesn't recognize the necessary pytest fixtures.
# pylint: disable-next=unused-import
from common import ExampleCredential, valid_credential, attributes, sho, issuer_key, master_key, hiding_keys
from kvac.credential_presentation import HiddenAttribute

from kvac.verifiable_encryption import AttributeRepresentationForEncryption as AttributeRepresentationForHiding, \
    MessageToEncrypt as MessageToHide


# pytest fixtures constantly redefine outer names, so ignore the warning.
# pylint: disable=redefined-outer-name


class TestPresentation:
    """Tests for the issuance presentation."""
    def test_correct_arguments_blinded(self, valid_credential, attributes, hiding_keys):
        presentation = valid_credential.present(
            hiding_keys=hiding_keys
        )

        presentation_attributes = [attribute.value for attribute in presentation.attributes]
        hidden_attr_idx = 0
        # Credential.attributes is iterable
        # pylint: disable-next=not-an-iterable
        for a in ExampleCredential.clear_attributes() + ExampleCredential.blind_attributes():
            if a.hidden:
                assert hiding_keys[hidden_attr_idx].encrypt(
                    AttributeRepresentationForHiding.encode(attributes[a.name])
                ) in presentation_attributes
                hidden_attr_idx += 1
            else:
                assert attributes[a.name] in presentation_attributes

    def test_valid(self, valid_credential, issuer_key, hiding_keys):
        presentation = valid_credential.present(
            hiding_keys=hiding_keys
        )

        assert valid_credential.verify_presentation(presentation=presentation, issuer_key=issuer_key) is True

    def test_invalid(self, valid_credential, issuer_key, hiding_keys, sho):
        presentation = valid_credential.present(
            hiding_keys=hiding_keys
        )

        hidden_attribute = presentation.attributes[1]
        presentation.attributes[1] = HiddenAttribute(
            value=hiding_keys[0].encrypt(
                AttributeRepresentationForHiding.encode(MessageToHide(
                    sho.squeeze(16),
                    sho.squeeze(23)
                ))
            ),
            commitment=hidden_attribute.commitment,
            hiding_key_commitment=hidden_attribute.hiding_key_commitment
        )

        assert valid_credential.verify_presentation(presentation=presentation, issuer_key=issuer_key) is False
