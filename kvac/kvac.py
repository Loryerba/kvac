from __future__ import annotations
from typing import List, Tuple, NamedTuple, Any, Optional

from kvac.mac import MACTag
from kvac.issuer_key_pair import IssuerPublicKey, IssuerKeyPair
from kvac.elgamal import ElGamalKeyPair
from kvac.commitment import BlindAttributeCommitment
from kvac.errors import VerificationError
from kvac.issuance_request import IssuanceRequest
from kvac.issuance_response import IssuanceResponse


class AttributeValue(NamedTuple):
    """AttributeValue is the object that stores the value of an attribute in an
    instance of KVAC."""

    value: Any
    blind: bool  # True if this is a blind attribute.


class Attribute:
    """This descriptor is used to declare an attribute of a KVAC.
    An Attribute is a class variable on the KVAC that indicates the presence of
    a certain attribute on the KVAC. The value of the attribute for an instance of
    a KVAC is stored in the KVAC as a private instance variable of type AttributeValue.
    See the documentation of the KVAC class for usage information."""

    def __init__(self, blind: bool = False):
        self._blind: bool = blind
        self._name: str = ""
        self._private_name: str = ""

    def __set_name__(self, owner, name):
        self._name = name
        self._private_name = f"_{name}"

    def __get__(self, obj, objtype=None) -> Any:
        value = getattr(obj, self._private_name, None)
        if value is None:
            raise AttributeError(f"attribute '{self.name}' has no value assigned")
        return value.value

    def __set__(self, obj, value):
        if getattr(obj, self._private_name, None) is not None:
            raise AttributeError(f"can't set attribute '{self.name}' more than once")
        setattr(obj, self._private_name, AttributeValue(value=value, blind=self.blind))

    @property
    def blind(self):
        """Returns whether the attribute is blinded during issuance."""
        return self._blind

    @property
    def name(self):
        """Returns the name of the attribute in the KVAC."""
        return self._name


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

    1. The user creates an issuance request

        request, user_key = Credential.request(
            issuer_public_key,
            normal_attribute=...,
            another_normal_attribute=...,
            blind_attribute=...)

    and sends the request to the issuer. The user_key is kept secret.

    2. The issuer creates an issuance response

        response = Credential.issue(issuer_secret_key, request)

    and sends the response to the user.

    3. The user creates the KVAC from the response:

        kvac = Credential(
            issuer_public_key,
            user_key,
            request,
            response)

    4. TODO Presentation
    5. TODO Verification
    """

    def __init__(
        self,
        *,
        issuer_key: IssuerPublicKey,
        user_key: ElGamalKeyPair,
        request: IssuanceRequest,
        response: IssuanceResponse,
    ):
        if response.verify(issuer_key, request) is False:
            raise VerificationError(
                "Invalid issuance response. This could mean that the issuer is malicious."
            )

        self.tag: MACTag = response.tag.decrypt(user_key)

        for attribute, request_clear_attribute in zip(
            self.clear_attributes(), request.clear_attributes
        ):
            setattr(self, attribute.name, request_clear_attribute)
        for attribute, request_blind_attribute in zip(
            self.blind_attributes(), request.blinded_attributes
        ):
            setattr(self, attribute.name, user_key.decrypt(request_blind_attribute))

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

    @classmethod
    def blind_attributes(cls) -> List[Attribute]:
        """Returns the attributes that are blinded during issuance."""
        # cls.attributes is iterable.
        # pylint: disable-next=not-an-iterable
        return [attribute for attribute in cls.attributes() if attribute.blind is True]

    @classmethod
    def request(
        cls, *, issuer_key: IssuerPublicKey, **kwargs: Any
    ) -> Tuple[IssuanceRequest, ElGamalKeyPair]:
        """Request a new KVAC.
        For each attribute of the credential, there needs to be one named argument
        with its value given.

        Called by the user."""

        available_attributes = set(map(lambda a: a.name, cls.attributes()))
        given_attributes = set(kwargs.keys())
        if not set(available_attributes).issubset(given_attributes):
            raise ValueError(
                f"missing value for attribute(s): {available_attributes - given_attributes}"
            )

        clear_attributes = []
        blind_attributes = []
        # cls.attributes is iterable.
        # pylint: disable-next=not-an-iterable
        for attribute in cls.attributes():
            if attribute.blind:
                blind_attributes.append(kwargs[attribute.name])
            else:
                clear_attributes.append(kwargs[attribute.name])

        return IssuanceRequest.new(issuer_key, clear_attributes, blind_attributes)

    @classmethod
    def issue(
        cls,
        *,
        issuer_key: IssuerKeyPair,
        request: IssuanceRequest,
        commitment: Optional[BlindAttributeCommitment] = None,
    ) -> IssuanceResponse:
        """Issues a new KVAC and generates the issuance response.
        If a commitment is given, also check that the blinded values committed
        to in the request matches the given commitment.

        Called by the issuer.
        """

        if commitment is not None:
            if request.commitment != commitment:
                raise VerificationError(
                    "Commitment in request does not match given commitment."
                )

        if request.verify(issuer_key.public, request.blinding_key) is False:
            raise VerificationError(
                "Invalid issuance request. This could mean that the user is malicious."
            )

        return IssuanceResponse.new(issuer_key, request)
