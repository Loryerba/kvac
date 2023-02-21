from __future__ import annotations

from collections.abc import Iterable
from enum import Enum
from typing import List, Tuple, NamedTuple, Any, Optional, Type

from poksho.group.ristretto import RistrettoPoint

from kvac.credential_presentation import CredentialPresentation
from kvac.mac import MACTag
from kvac.issuer_key import IssuerPublicKey, IssuerKeyPair
from kvac.elgamal import ElGamalKeyPair
from kvac.commitment import BlindAttributeCommitment
from kvac.exceptions import VerificationFailure, CallNotAllowed
from kvac.issuance_request import IssuanceRequest
from kvac.issuance_response import IssuanceResponse
from kvac.verifiable_encryption import KeyPair as HidingKeyPair, \
    AttributeRepresentationForEncryption as AttributeRepresentationForHiding, \
    MessageToEncrypt as MessageToHide


def to_list(value_or_iterable):
    """Converts an iterable to a list or produces a list with a single element
    if the argument is not iterable."""
    if isinstance(value_or_iterable, Iterable):
        return list(value_or_iterable)
    return [value_or_iterable]

class AttributeValue(NamedTuple):
    """AttributeValue is the object that stores the value of an attribute in an
    instance of KVAC."""

    value: Tuple[RistrettoPoint] | AttributeRepresentationForHiding
    scalar: bool  # True if this is a scalar attribute. Scalar attributes can not be hidden.
    blind: bool   # True if this is a blind attribute during issuance.
    hidden: bool  # True if this is a hidden attribute during presentation.


class Attribute:
    """This descriptor is used to declare an attribute of a KVAC.
    An Attribute is a class variable on the KVAC that indicates the presence of
    a certain attribute on the KVAC. The value of the attribute for an instance of
    a KVAC is stored in the KVAC as a private instance variable of type AttributeValue.
    See the documentation of the KVAC class for usage information."""

    def __init__(self, *, blind: bool = False, hidden: bool = False, scalar: bool = False):
        if scalar and hidden:
            raise ValueError("scalar attribute can not be hidden")

        self._blind: bool = blind
        self._hidden: bool = hidden
        self._scalar: bool = scalar
        self._name: str = ""
        self._private_name: str = ""
        self._index: int

    def __set_name__(self, owner: Type[KVAC], name: str):
        self._name = name
        self._private_name = f"_{name}"

        self._index = self.index_in_kvac(owner)

    def __get__(self, obj: KVAC, objtype: Optional[Type] = None) -> Any:
        attribute = getattr(obj, self._private_name, None)
        if attribute is None:
            raise AttributeError(f"{obj} has no attribute '{self.name}'")

        if self.hidden:
            return attribute.value.decode()

        return attribute.value

    def get_internal_representation(self, obj: KVAC):
        attribute = getattr(obj, self._private_name, None)
        if attribute is None:
            raise AttributeError(f"attribute '{self.name}' has no value assigned")

        if self.scalar:
            return obj.issuer_public_key.system.G_ms[self.index] ** attribute.value

        return attribute.value

    def __set__(self, obj: KVAC, value: Any):
        if getattr(obj, self._private_name, None) is not None:
            raise AttributeError(f"can't set attribute '{self.name}' more than once")

        if self.hidden:
            if not isinstance(value, MessageToHide):
                raise ValueError(f"attribute '{self.name}' is a hidden attribute, please specify a "
                                 f"MessageToHide object")
            value = AttributeRepresentationForHiding.encode(value)

        setattr(obj, self._private_name, AttributeValue(value=value,
                                                        blind=self.blind,
                                                        hidden=self.hidden,
                                                        scalar=self.scalar))

    def index_in_kvac(self, owner: Type[KVAC]):
        index = 0
        for attribute in owner.attributes():
            if attribute is self:
                break

            if attribute.hidden:
                index += 2 # hidden attributes consist of 2 attributes internally
            else:
                index += 1
        return index

    @property
    def blind(self):
        """Returns whether the attribute is blinded during issuance."""
        return self._blind

    @property
    def hidden(self):
        """Returns whether the attribute is hidden during presentation."""
        return self._hidden

    @property
    def scalar(self):
        """Returns whether the attribute is a scalar."""
        return self._scalar

    @property
    def name(self):
        """Returns the name of the attribute in the KVAC."""
        return self._name

    @property
    def index(self):
        """Returns the position of this attribute in the list of all attributes of the credential."""
        return self._index


class KVAC:
    """Represents a Keyed-Verification Anonymous Credential (KVAC).

    To implement a credential with specific attributes, inherit from this class
    and mark class variables as attributes:

        class Credential(KVAC):
            normal_attribute = Attribute()
            another_normal_attribute = Attribute()
            blind_attribute = Attribute(blind=True)

    On instances of the Credential class, the values of the attribute class variables
    are available as instance variable.

    The lifecycle of a KVAC is as follows:

    1. The user creates an *inactive* credential populated with values for all credential
    attributes:

        kvac = Credential(
            issuer_public_key=...
            normal_attribute=...,
            another_normal_attribute=...,
            blind_attribute=...
        )

    2. The user creates an issuance request using the inactive credential

        request, user_key = kvac.request()

    and sends the request to the issuer. The user_key is kept secret.

    2. The issuer creates an issuance response

        response = Credential.issue(issuer_secret_key, request)

    and sends the response to the user.

    3. The user activates the KVAC using the response:

        kvac.activate(response)

    4. The user creates a presentation using his (now *active*) KVAC and a set of hiding keys for the
        hidden attributes:

        presentation = kvac.present(
            hiding_keys
        )

    5. Finally, the issuer can verify the presentation using his secret key:

        Credential.verify_present(
            issuer_secret_key,
            presentation
        )
    """

    class ProcessStage(Enum):
        """
        This class indicates the stage we have currently reached in obtaining a credential.
        It is used to ensure we do the required steps (see above) in the correct order.
        """
        CREDENTIAL_INACTIVE = 0
        ISSUANCE_REQUESTED = 1
        CREDENTIAL_ACTIVE = 2

    issuer_public_key: IssuerPublicKey
    process_stage: KVAC.ProcessStage

    issuance_request: IssuanceRequest
    user_key: ElGamalKeyPair
    tag: MACTag

    def __init__(self, *, issuer_key: IssuerPublicKey, **kwargs: Any):
        self.issuer_public_key: IssuerPublicKey = issuer_key

        available_attributes = set(map(lambda a: a.name, self.attributes()))
        given_attributes = set(kwargs.keys())
        if not set(available_attributes).issubset(given_attributes):
            raise ValueError(
                f"missing value for attribute(s): {available_attributes - given_attributes}"
            )

        for attribute in self.attributes():
            setattr(self, attribute.name, kwargs[attribute.name])

        self.process_stage = self.ProcessStage.CREDENTIAL_INACTIVE

    @classmethod
    def number_of_attribute_components(cls) -> int:
        """
        Returns the total number of attribute components across all attributes of this credential.
        Should be used to determine how many attribute an issuer key pair should have.
        """
        return len(cls.revealed_attributes()) + 2 * len(cls.hidden_attributes())

    @classmethod
    def attributes(cls) -> List[Attribute]:
        """Returns the attributes of this credential."""
        return [
            member for member in vars(cls).values() if isinstance(member, Attribute)
        ]

    @classmethod
    def clear_attributes(cls) -> List[Attribute]:
        """Returns the attributes that are not blinded during issuance."""
        # cls.attributes is iterable.
        # pylint: disable-next=not-an-iterable
        return [attribute for attribute in cls.attributes() if attribute.blind is False]

    def clear_attribute_components(self):
        """
        Returns the flattened version of all attribute components that are not blinded
        during issuance.

        Each attribute may consist of two components depending on whether it is going to be
        hidden during presentation. However, during the issuance, we can treat these
        components as separate attributes.
        """
        attributes = []
        for attribute in self.clear_attributes():
            attributes += to_list(attribute.get_internal_representation(self))
        return attributes

    @classmethod
    def blind_attributes(cls) -> List[Attribute]:
        """Returns the attributes that are blinded during issuance."""
        # cls.attributes is iterable.
        # pylint: disable-next=not-an-iterable
        return [attribute for attribute in cls.attributes() if attribute.blind is True]

    def blind_attribute_components(self):
        """
        Returns the flattened version of all attribute components that are blinded
        during issuance.

        Each attribute may consist of two components depending on whether it is going to be
        hidden during presentation. However, during the issuance, we can treat these
        components as separate attributes.
        """
        attributes = []
        for attribute in self.blind_attributes():
            attributes += to_list(attribute.get_internal_representation(self))
        return attributes

    def request(self) -> Tuple[IssuanceRequest, BlindAttributeCommitment]:
        """Request a new KVAC.

        Called by the user."""
        issuance_request, user_key = IssuanceRequest.new(
            self.issuer_public_key,
            self.clear_attribute_components(),
            self.blind_attribute_components()
        )
        self.issuance_request = issuance_request
        self.user_key = user_key
        self.process_stage = self.ProcessStage.ISSUANCE_REQUESTED

        return issuance_request, self.commit_blinded_attributes()

    def commit_blinded_attributes(self):
        """Creates a commitment on the attributes blinded during issuance."""
        return BlindAttributeCommitment.new(
            self.issuer_public_key,
            self.blind_attribute_components()
        )

    @classmethod
    def issue(
        cls,
        *,
        issuer_key: IssuerKeyPair,
        request: IssuanceRequest,
        commitment: Optional[BlindAttributeCommitment] = None,
    ) -> IssuanceResponse:
        """Issues a new KVAC and generates the issuance response.
        Also checks that the blinded values committed to in the request matches
        the given commitment.

        Called by the issuer.
        """

        if len(request.blinded_attributes) > 0:
            if commitment is None:
                raise ValueError(
                    "commitment is required if blind attributes are given."
                )

            if request.commitment != commitment:
                raise VerificationFailure(
                    "Commitment in request does not match given commitment."
                )

        if request.verify(issuer_key.public, request.blinding_key) is False:
            raise VerificationFailure(
                "Invalid issuance request. This could mean that the user is malicious."
            )

        return IssuanceResponse.new(issuer_key, request)

    def activate(self, response: IssuanceResponse):
        """Activates the credential with a tag from an issuance response so that it can be presented."""
        if self.process_stage != self.ProcessStage.ISSUANCE_REQUESTED:
            raise CallNotAllowed(
                "Cannot activate the credential before having created a issuance request."
            )

        if response.verify(self.issuer_public_key, self.issuance_request) is False:
            raise VerificationFailure(
                "Invalid issuance response. This could mean that the issuer is malicious."
            )

        self.tag = response.tag.decrypt(self.user_key)
        self.process_stage = self.ProcessStage.CREDENTIAL_ACTIVE

    @classmethod
    def revealed_attributes(cls) -> List[Attribute]:
        """Returns the attributes that are not hidden during presentation."""
        # cls.attributes is iterable.
        # pylint: disable-next=not-an-iterable
        return [attribute for attribute in cls.attributes() if attribute.hidden is False]

    @classmethod
    def hidden_attributes(cls) -> List[Attribute]:
        """Returns the attributes that are hidden during presentation."""
        # cls.attributes is iterable.
        # pylint: disable-next=not-an-iterable
        return [attribute for attribute in cls.attributes() if attribute.hidden is True]

    def present(self, hiding_keys: Optional[List[HidingKeyPair]]) -> CredentialPresentation:
        """Creates a presentation for the credential.
        :param hiding_keys  One hiding key for each attribute to hide.
                            Can be omitted iff there are no hidden attributes whatsoever.

        Called by the user."""

        if self.process_stage != self.ProcessStage.CREDENTIAL_ACTIVE:
            raise CallNotAllowed(
                "Cannot present a credential without having received a tag."
            )

        hiding_pattern = []
        attributes = []
        # We need to use the attributes in this order to match the order of the issuance (proof)
        # during presentation.
        for attribute in self.clear_attributes() + self.blind_attributes():
            hiding_pattern.append(attribute.hidden)
            attributes.append(attribute.get_internal_representation(self))

        hiding_keys = hiding_keys or []
        if 0 < len(self.hidden_attributes()) != len(hiding_keys):
            raise ValueError("There must be one hiding key given for each attribute to hide")

        return CredentialPresentation.new(self.tag, self.issuer_public_key, hiding_pattern, attributes, hiding_keys)

    @classmethod
    def verify_presentation(cls, *, issuer_key: IssuerKeyPair, presentation: CredentialPresentation) -> bool:
        """Verifies a credential presentation.

        Called by the issuer."""

        return presentation.verify(issuer_key)
