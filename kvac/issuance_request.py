from __future__ import annotations
from typing import List, NamedTuple, Tuple

from poksho.equation import Element as SymbolicElement, Exponent as SymbolicExponent

from poksho.group.ristretto import RistrettoPoint
from poksho.statement import Statement, Proof, Equation
from poksho.group.ristretto import Group as RistrettoGroup

from kvac.issuer_key import IssuerPublicKey
from kvac.elgamal import (
    ElGamalKeyPair,
    ElGamalPublicKey,
    ElGamalCiphertext,
    ElGamalCiphertextWithSecretNonce,
)
from kvac.commitment import (
    BlindAttributeCommitment,
    BlindAttributeCommitmentWithSecretNonce,
)


class IssuanceRequest(NamedTuple):
    """Represents the request to be issued a KVAC.
    It is created by the user and sent to the issuer."""

    clear_attributes: List[RistrettoPoint]
    blinded_attributes: List[ElGamalCiphertext]
    commitment: BlindAttributeCommitment
    proof_blind_attributes_match_commitment: Proof
    blinding_key: ElGamalPublicKey

    @classmethod
    def new(
        cls,
        issuer_key: IssuerPublicKey,
        clear_attributes: List[RistrettoPoint],
        blind_attributes: List[RistrettoPoint],
    ) -> Tuple[IssuanceRequest, ElGamalKeyPair]:
        """Create a new issuance request. Called by the user."""

        user_key = ElGamalKeyPair.generate(issuer_key.system.G)

        blinded_attributes = [
            user_key.public.encrypt_and_return_secret_nonce(a) for a in blind_attributes
        ]

        commitment_with_secret_nonce = BlindAttributeCommitmentWithSecretNonce.new(
            issuer_key, blind_attributes
        )

        statement = IssuanceRequestStatement.new(len(blind_attributes))
        statement.bind_public_values(
            issuer_key,
            user_key.public,
            [a.ciphertext for a in blinded_attributes],
            commitment_with_secret_nonce.C,
        )
        statement.bind_secret_values(
            user_key, commitment_with_secret_nonce, blinded_attributes
        )
        proof = statement.prove()

        return (
            cls(
                clear_attributes=clear_attributes,
                blinded_attributes=[a.ciphertext for a in blinded_attributes],
                commitment=commitment_with_secret_nonce.C,
                proof_blind_attributes_match_commitment=proof,
                blinding_key=user_key.public,
            ),
            user_key,
        )

    def verify(self, issuer_key: IssuerPublicKey, user_key: ElGamalPublicKey) -> bool:
        """Verifies that the user included a valid proof that the values of the
        blinded attributes match a commitment.
        Called by the issuer."""
        statement = IssuanceRequestStatement.new(len(self.blinded_attributes))
        statement.bind_public_values(
            issuer_key, user_key, self.blinded_attributes, self.commitment
        )
        return statement.verify(self.proof_blind_attributes_match_commitment) is True


class IssuanceRequestStatement(NamedTuple):
    """Statement proving that the blinded attributes given by the user in the
    IssuanceRequest match a commitment to these attributes."""

    # public values
    Y: SymbolicElement
    G: SymbolicElement
    C1s: List[SymbolicElement]
    C2s_div_Js: List[SymbolicElement]
    J_r: SymbolicElement
    G_r: SymbolicElement
    inverse_G_js: List[SymbolicElement]

    # private values
    y: SymbolicExponent
    j_r: SymbolicExponent
    rs: List[SymbolicExponent]

    statement: Statement

    @classmethod
    def new(cls, number_of_blinded_attributes: int) -> IssuanceRequestStatement:
        # pylint: disable=too-many-locals
        Y = SymbolicElement("Y")
        G = SymbolicElement("G")

        C1s = [
            SymbolicElement(f"C1{i}")
            for i in range(1, number_of_blinded_attributes + 1)
        ]
        C2s_div_Js = [
            SymbolicElement(f"C2{i}_div_J{i}")
            for i in range(1, number_of_blinded_attributes + 1)
        ]

        J_r = SymbolicElement("J_r")
        G_r = SymbolicElement("G_r")
        inverse_G_js = [
            SymbolicElement(f"G_j{i}**-1")
            for i in range(1, number_of_blinded_attributes + 1)
        ]

        y = SymbolicExponent("y")
        j_r = SymbolicExponent("j_r")
        rs = [
            SymbolicExponent(f"r{i}")
            for i in range(1, number_of_blinded_attributes + 1)
        ]

        statement = Statement(
            RistrettoGroup, Equation(Y, G**y), Equation(J_r, G_r**j_r)
        )

        for C1, C2_div_J, r, inverse_G_j in zip(C1s, C2s_div_Js, rs, inverse_G_js):
            statement.add_equation(
                Equation(C1, G**r), Equation(C2_div_J, Y**r * inverse_G_j**j_r)
            )

        return cls(
            Y=Y,
            G=G,
            C1s=C1s,
            C2s_div_Js=C2s_div_Js,
            J_r=J_r,
            G_r=G_r,
            inverse_G_js=inverse_G_js,
            y=y,
            j_r=j_r,
            rs=rs,
            statement=statement,
        )

    def bind_public_values(
        self,
        issuer_key: IssuerPublicKey,
        user_key: ElGamalPublicKey,
        blinded_attributes: List[ElGamalCiphertext],
        commitment: BlindAttributeCommitment,
    ):

        self.Y.bind(user_key.key)
        self.G.bind(issuer_key.system.G)

        for C1, attribute in zip(self.C1s, blinded_attributes):
            C1.bind(attribute.c1)
        for C2_div_J, attribute, J in zip(
            self.C2s_div_Js, blinded_attributes, commitment.Js
        ):
            C2_div_J.bind(attribute.c2 / J)

        self.J_r.bind(commitment.Jr)
        self.G_r.bind(issuer_key.system.G_r)
        for inverse_G_j, G_j_value in zip(self.inverse_G_js, issuer_key.system.G_js):
            inverse_G_j.bind(-G_j_value)

    def bind_secret_values(
        self,
        user_key: ElGamalKeyPair,
        commitment: BlindAttributeCommitmentWithSecretNonce,
        blinded_attributes: List[ElGamalCiphertextWithSecretNonce],
    ):
        self.y.bind(user_key.secret)
        self.j_r.bind(commitment.j_r)
        for r, blind_attribute in zip(self.rs, blinded_attributes):
            r.bind(blind_attribute.r)

    def prove(self) -> Proof:
        return self.statement.prove()

    def verify(self, proof: Proof) -> bool:
        return self.statement.verify(proof)
