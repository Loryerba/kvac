from __future__ import annotations

from typing import NamedTuple, List, Tuple, cast

from poksho.group.ristretto import Group as RistrettoGroup, RistrettoPoint, RistrettoScalar
from poksho.statement import Proof, Statement
from poksho.equation import Element as SymbolicElement, Exponent as SymbolicExponent, Equation

from kvac.issuer_key import IssuerPublicKey, IssuerKeyPair
from kvac.mac import TagCommitment, MACTag
from kvac.verifiable_encryption import KeyPair as HidingKeyPair, KeyCommitment as HidingKeyCommitment, \
    Ciphertext as HiddenAttributeCiphertext, AttributeRepresentationForEncryption as AttributeRepresentationForHiding


class RevealedAttribute(NamedTuple):
    """
    This class represents a revealed attribute in a credential presentation.
    """
    value: RistrettoPoint
    commitment: RistrettoPoint

    @staticmethod
    def create(G_y: RistrettoPoint, z: RistrettoScalar, attribute: RistrettoPoint):
        value = attribute
        commitment = G_y ** z

        return RevealedAttribute(
            value=value,
            commitment=commitment
        )


class HiddenAttribute(NamedTuple):
    """
    This class represents a hidden attribute in a credential presentation.
    """
    value: HiddenAttributeCiphertext
    commitment: Tuple[RistrettoPoint, RistrettoPoint]
    hiding_key_commitment: HidingKeyCommitment

    @staticmethod
    def create(G_y1: RistrettoPoint,
               G_y2: RistrettoPoint,
               hiding_key: HidingKeyPair,
               z: RistrettoScalar,
               attribute: AttributeRepresentationForHiding):
        value = hiding_key.encrypt(attribute)
        commitment = G_y1 ** z * attribute.M_1, G_y2 ** z * attribute.M_2
        hiding_key_commitment = hiding_key.commitment

        return HiddenAttribute(
            value=value,
            commitment=commitment,
            hiding_key_commitment=hiding_key_commitment
        )


class CredentialPresentation(NamedTuple):
    """Represents a presentation of a credential.
    It is created by the user and send to the issuer."""

    proof_credential_is_valid: Proof
    tag_commitment: TagCommitment
    attributes: List[RevealedAttribute | HiddenAttribute]

    @classmethod
    def new(cls,
            tag: MACTag,
            issuer_key: IssuerPublicKey,
            hiding_pattern: List[bool],
            attributes: List[RistrettoPoint | AttributeRepresentationForHiding],
            hiding_keys: List[HidingKeyPair]) -> CredentialPresentation:
        """Creates a new issuance presentation for a KVAC.
        Called by the user."""
        statement = PresentationStatement.new(
            hiding_pattern
        )

        tag_commitment, z = tag.commit_and_return_secret_nonce(issuer_key)

        G_y_iter, hiding_key_iter = iter(issuer_key.system.G_ys), iter(hiding_keys)
        presented_attributes: List[RevealedAttribute | HiddenAttribute] = [
            HiddenAttribute.create(
                next(G_y_iter), next(G_y_iter), next(hiding_key_iter),
                z, cast(AttributeRepresentationForHiding, attribute)
            )
            if is_hidden
            else RevealedAttribute.create(
                next(G_y_iter), z, cast(RistrettoPoint, attribute)
            )
            for attribute, is_hidden in zip(attributes, hiding_pattern)
        ]

        statement.bind_public_values(
            tag_commitment,
            issuer_key,
            presented_attributes
        )
        statement.bind_secret_values(
            tag,
            z,
            hiding_keys
        )
        proof = statement.prove()

        return cls(
            proof_credential_is_valid=proof,
            tag_commitment=tag_commitment,
            attributes=presented_attributes
        )

    def verify(self, issuer_key: IssuerKeyPair) -> bool:
        """Verifies that this presentation belongs to a valid credential.
        Called by the issuer."""
        statement = PresentationStatement.new(
            [isinstance(attribute, HiddenAttribute) for attribute in self.attributes]
        )

        if not self.verify_Z(issuer_key):
            return False

        statement.bind_public_values(
            self.tag_commitment,
            issuer_key.public,
            self.attributes
        )
        return statement.verify(self.proof_credential_is_valid) is True

    def verify_Z(self, issuer_key: IssuerKeyPair):
        """
        Recompute the Z value of the attribute commitment using the issuer secret key to
        verify that the presented credential was actually issued by this key.
        """
        Z = self.tag_commitment.C_V
        Z /= issuer_key.public.system.G_w ** issuer_key.secret.w
        Z /= self.tag_commitment.C_x0 ** issuer_key.secret.x0
        Z /= self.tag_commitment.C_x1 ** issuer_key.secret.x1

        secret_key_itr = iter(issuer_key.secret.ys)
        for attribute in self.attributes:
            if isinstance(attribute, HiddenAttribute):
                y1, y2 = next(secret_key_itr), next(secret_key_itr)
                Z /= attribute.commitment[0] ** y1
                Z /= attribute.commitment[1] ** y2
            else:
                y = next(secret_key_itr)
                Z /= (attribute.commitment * attribute.value) ** y

        return Z == self.tag_commitment.Z


class PresentationStatement(NamedTuple):
    """Statement proving that the user knows a credential for a set of revealed and hidden attributes."""

    # public values
    I: SymbolicElement
    Z: SymbolicElement
    C_x0: SymbolicElement
    C_x1: SymbolicElement
    C_V: SymbolicElement
    G_x0: SymbolicElement
    G_x1: SymbolicElement
    G_ys: List[SymbolicElement]
    G_e1s: List[SymbolicElement]
    G_e2s: List[SymbolicElement]
    C_ys: List[SymbolicElement]
    C_es: List[SymbolicElement]
    E_1s: List[SymbolicElement]
    inverse_E_1s: List[SymbolicElement]
    C_y2_div_E_2s: List[SymbolicElement]

    # private values
    t: SymbolicExponent
    z: SymbolicExponent
    z_e0: SymbolicExponent
    z_es: List[SymbolicExponent]
    e_sk1s: List[SymbolicExponent]
    e_sk2s: List[SymbolicExponent]

    statement: Statement

    @classmethod
    def new(cls, hiding_pattern: List[bool]) -> PresentationStatement:
        # pylint: disable=too-many-locals
        number_of_hidden_attributes = sum(hiding_pattern)
        number_of_clear_attributes = len(hiding_pattern) - number_of_hidden_attributes
        number_of_attribute_components = number_of_clear_attributes + 2 * number_of_hidden_attributes

        I = SymbolicElement("I")
        Z = SymbolicElement("Z")
        C_x0 = SymbolicElement("C_x0")
        C_x1 = SymbolicElement("C_x1")
        C_V = SymbolicElement("C_V")

        G_x0 = SymbolicElement("G_x0")
        G_x1 = SymbolicElement("G_x1")
        G_ys = [SymbolicElement(f"G_y{i}") for i in range(1, number_of_attribute_components + 1)]

        C_ys = [SymbolicElement(f"C_y{i}") for i in range(1, number_of_attribute_components + 1)]

        G_e1s = [SymbolicElement(f"G_e1{i}") for i in range(1, number_of_hidden_attributes + 1)]
        G_e2s = [SymbolicElement(f"G_e2{i}") for i in range(1, number_of_hidden_attributes + 1)]
        C_es = [SymbolicElement(f"C_e{i}") for i in range(1, number_of_hidden_attributes + 1)]
        E_1s = [SymbolicElement(f"E_1{i}") for i in range(1, number_of_hidden_attributes + 1)]
        inverse_E_1s = [SymbolicElement(f"inverse_E_1{i}") for i in range(1, number_of_hidden_attributes + 1)]
        C_y2_div_E_2s = [SymbolicElement(f"C_y2{i}_div_E_2{i}") for i in range(1, number_of_attribute_components + 1)]

        t = SymbolicExponent("t")
        z = SymbolicExponent("z")
        z_e0 = SymbolicExponent("z_e0")
        z_es = [SymbolicExponent(f"z_e{i}") for i in range(1, number_of_hidden_attributes + 1)]
        e_sk1s = [SymbolicExponent(f"e_sk1{i}") for i in range(1, number_of_hidden_attributes + 1)]
        e_sk2s = [SymbolicExponent(f"e_sk2{i}") for i in range(1, number_of_hidden_attributes + 1)]

        statement = Statement(
            RistrettoGroup,
            # MAC Tag (commitment) validation
            Equation(Z, I ** z),
            Equation(C_x1, C_x0 ** t * G_x0 ** z_e0 * G_x1 ** z)
        )

        hidden_attr_idx = 0
        index_y = 0
        for is_hidden_attribute in hiding_pattern:
            if is_hidden_attribute:
                # Hidden attribute validation
                # Used hiding key belongs to commitment
                C_e, G_e1, G_e2 = C_es[hidden_attr_idx], G_e1s[hidden_attr_idx], G_e2s[hidden_attr_idx]
                e_sk1, e_sk2 = e_sk1s[hidden_attr_idx], e_sk2s[hidden_attr_idx]
                statement.add_equation(
                    Equation(C_e, G_e1 ** e_sk1 * G_e2 ** e_sk2),
                )
                # Committed plaintext is the same as encrypted plaintext
                C_y2_div_E_2, G_y2 = C_y2_div_E_2s[index_y + 1], G_ys[index_y + 1]
                inverse_E_1, e_sk2 = inverse_E_1s[hidden_attr_idx], e_sk2s[hidden_attr_idx]
                statement.add_equation(
                    Equation(C_y2_div_E_2, G_y2 ** z * inverse_E_1 ** e_sk2)
                )
                # Ciphertext is well-formed
                E_1, e_sk1, z_e = E_1s[hidden_attr_idx], e_sk1s[hidden_attr_idx], z_es[hidden_attr_idx]
                C_y, G_y = C_ys[index_y], G_ys[index_y]

                statement.add_equation(
                    Equation(E_1, C_y ** e_sk1 * G_y ** z_e)
                )

                hidden_attr_idx += 1
                index_y += 2
            else:
                # Revealed attribute validation
                C_y, G_y = C_ys[index_y], G_ys[index_y]
                statement.add_equation(
                    Equation(C_y, G_y ** z)
                )

                index_y += 1

        return cls(
            I=I,
            Z=Z,
            C_x0=C_x0,
            C_x1=C_x1,
            C_V=C_V,
            G_x0=G_x0,
            G_x1=G_x1,
            G_ys=G_ys,
            G_e1s=G_e1s,
            G_e2s=G_e2s,
            C_ys=C_ys,
            C_es=C_es,
            E_1s=E_1s,
            inverse_E_1s=inverse_E_1s,
            C_y2_div_E_2s=C_y2_div_E_2s,
            t=t,
            z=z,
            z_e0=z_e0,
            z_es=z_es,
            e_sk1s=e_sk1s,
            e_sk2s=e_sk2s,
            statement=statement,
        )

    def bind_public_values(
            self,
            tag_commitment: TagCommitment,
            issuer_key: IssuerPublicKey,
            presented_attributes: List[RevealedAttribute | HiddenAttribute],
    ):
        # pylint: disable=too-many-locals

        self.I.bind(issuer_key.I)
        self.Z.bind(tag_commitment.Z)
        self.C_x0.bind(tag_commitment.C_x0)
        self.C_x1.bind(tag_commitment.C_x1)
        self.C_V.bind(tag_commitment.C_V)

        self.G_x0.bind(issuer_key.system.G_x0)
        self.G_x1.bind(issuer_key.system.G_x1)
        for G_y, G_y_value in zip(self.G_ys, issuer_key.system.G_ys):
            G_y.bind(G_y_value)

        for G_e1, G_e2, encryption_params in zip(self.G_e1s, self.G_e2s, issuer_key.system.G_es):
            G_e1.bind(encryption_params.G_1)
            G_e2.bind(encryption_params.G_2)

        index_y = 0
        hidden_attr_idx = 0
        for attribute in presented_attributes:
            if isinstance(attribute, HiddenAttribute):
                C_y, C_y2 = self.C_ys[index_y], self.C_ys[index_y + 1]
                C_e = self.C_es[hidden_attr_idx]
                E_1, inverse_E_1 = self.E_1s[hidden_attr_idx], self.inverse_E_1s[hidden_attr_idx]
                C_y2_div_E_2 = self.C_y2_div_E_2s[index_y + 1]
                C_y.bind(attribute.commitment[0])
                C_y2.bind(attribute.commitment[1])
                C_e.bind(attribute.hiding_key_commitment.A)
                E_1.bind(attribute.value.E_1)
                inverse_E_1.bind(-attribute.value.E_1)
                C_y2_div_E_2.bind(C_y2.value / attribute.value.E_2)


                hidden_attr_idx += 1
                index_y += 2
            else:
                self.C_ys[index_y].bind(attribute.commitment)

                index_y += 1

    def bind_secret_values(
            self,
            tag: MACTag,
            tag_commitment_nonce: RistrettoScalar,
            encryption_keys: List[HidingKeyPair],
    ):
        self.t.bind(tag.t)
        self.z.bind(tag_commitment_nonce)
        self.z_e0.bind(-tag.t * tag_commitment_nonce)
        for z_e, e_sk1, e_sk2, encryption_key in zip(self.z_es, self.e_sk1s, self.e_sk2s, encryption_keys):
            z_e.bind(-encryption_key.secret.a_1 * tag_commitment_nonce)
            e_sk1.bind(encryption_key.secret.a_1)
            e_sk2.bind(encryption_key.secret.a_2)

    def prove(self) -> Proof:
        return self.statement.prove()

    def verify(self, proof: Proof) -> bool:
        return self.statement.verify(proof)
