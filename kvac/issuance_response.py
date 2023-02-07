from __future__ import annotations
from typing import List, NamedTuple, TYPE_CHECKING

from poksho.equation import Element as SymbolicElement, Exponent as SymbolicExponent

from poksho.group.ristretto import RistrettoPoint, RistrettoScalar
from poksho.statement import Statement, Proof, Equation
from poksho.group.ristretto import Group as RistrettoGroup

from kvac.mac import BlindMACTag, MAC
from kvac.issuer_key import IssuerPublicKey, IssuerKeyPair

if TYPE_CHECKING:
    from kvac.kvac import IssuanceRequest


class IssuanceResponse(NamedTuple):
    """Represents the response to a IssuanceRequest. Created by the issuer
    in response to a IssuanceResponse from the user."""

    tag: BlindMACTag
    proof_tag_calculated_correctly: Proof

    @classmethod
    def new(
        cls, issuer_key: IssuerKeyPair, request: IssuanceRequest
    ) -> IssuanceResponse:
        """Creates a new issuance response for a given IssuanceRequest.
        This creates the KVAC.
        Called by the issuer."""
        mac = MAC(issuer_key)
        tag, r = mac.blind_mac_and_return_secret_nonce(
            request.blinding_key, request.clear_attributes, request.blinded_attributes
        )

        statement = IssuanceResponseStatement.new(
            len(request.clear_attributes), len(request.blinded_attributes)
        )
        statement.bind_public_values(issuer_key.public, tag, request)
        statement.bind_secret_values(issuer_key, r)
        proof = statement.prove()

        return cls(tag=tag, proof_tag_calculated_correctly=proof)

    def verify(self, issuer_key: IssuerPublicKey, request: IssuanceRequest) -> bool:
        """Verifies that this is a valid response to the given request regarding
        the issuer key.
        Called by the user."""
        statement = IssuanceResponseStatement.new(
            len(request.clear_attributes), len(request.blinded_attributes)
        )
        statement.bind_public_values(issuer_key, self.tag, request)
        return statement.verify(self.proof_tag_calculated_correctly) is True


class IssuanceResponseStatement(NamedTuple):
    """Statement proving that the issuer calculated the credential correctly."""

    # public values
    C_W: SymbolicElement
    G_w: SymbolicElement
    G_wprime: SymbolicElement
    G_V_div_I: SymbolicElement
    G_x0: SymbolicElement
    G_x1: SymbolicElement
    G_ys: List[SymbolicElement]
    S1: SymbolicElement
    C1s: List[SymbolicElement]
    G: SymbolicElement
    S2: SymbolicElement
    C2s: List[SymbolicElement]
    Y: SymbolicElement
    Ms: List[SymbolicElement]
    U: SymbolicElement
    U_raised_to_t: SymbolicElement

    # private values
    w: SymbolicExponent
    wprime: SymbolicExponent
    x0: SymbolicExponent
    x1: SymbolicExponent
    ys: List[SymbolicExponent]
    rprime: SymbolicExponent

    statement: Statement

    @classmethod
    def new(
        cls, number_of_clear_attributes: int, number_of_blinded_attributes: int
    ) -> IssuanceResponseStatement:
        # pylint: disable=too-many-locals
        number_of_attributes = number_of_clear_attributes + number_of_blinded_attributes

        C_W = SymbolicElement("C_W")
        G_w = SymbolicElement("G_w")
        G_wprime = SymbolicElement("G_wprime")
        G_V_div_I = SymbolicElement("G_V_div_I")
        G_x0 = SymbolicElement("G_x0")
        G_x1 = SymbolicElement("G_x1")
        G_ys = [SymbolicElement(f"G_y{i}") for i in range(1, number_of_attributes + 1)]
        S1 = SymbolicElement("S1")
        C1s = [
            SymbolicElement(f"C1{i}")
            for i in range(1, number_of_blinded_attributes + 1)
        ]
        G = SymbolicElement("G")
        S2 = SymbolicElement("S2")
        C2s = [
            SymbolicElement(f"C2{i}")
            for i in range(1, number_of_blinded_attributes + 1)
        ]
        Y = SymbolicElement("Y")
        Ms = [
            SymbolicElement(f"M{i}") for i in range(1, number_of_clear_attributes + 1)
        ]
        U = SymbolicElement("U")
        U_raised_to_t = SymbolicElement("U_raised_to_t")

        w = SymbolicExponent("w")
        wprime = SymbolicExponent("wprime")
        x0 = SymbolicExponent("x0")
        x1 = SymbolicExponent("x1")
        ys = [SymbolicExponent(f"y{i}") for i in range(1, number_of_attributes + 1)]
        rprime = SymbolicExponent("rprime")

        term_G_V_div_I = G_x0**x0 * G_x1**x1
        for G_y, y in zip(G_ys, ys):
            term_G_V_div_I *= G_y**y

        term_s1 = G**rprime
        for C1, y in zip(C1s, ys[-number_of_blinded_attributes:]):
            term_s1 *= C1**y

        term_s2 = Y**rprime * G_w**w * U**x0 * U_raised_to_t**x1
        for M, y in zip(Ms, ys):
            term_s2 *= M**y
        for C2, y in zip(C2s, ys[-number_of_blinded_attributes:]):
            term_s2 *= C2**y

        statement = Statement(
            RistrettoGroup,
            Equation(C_W, G_w**w * G_wprime**wprime),
            Equation(G_V_div_I, term_G_V_div_I),
            Equation(S1, term_s1),
            Equation(S2, term_s2),
        )

        return cls(
            C_W=C_W,
            G_w=G_w,
            G_wprime=G_wprime,
            G_V_div_I=G_V_div_I,
            G_x0=G_x0,
            G_x1=G_x1,
            G_ys=G_ys,
            S1=S1,
            C1s=C1s,
            G=G,
            S2=S2,
            C2s=C2s,
            Y=Y,
            Ms=Ms,
            U=U,
            U_raised_to_t=U_raised_to_t,
            w=w,
            wprime=wprime,
            x0=x0,
            x1=x1,
            ys=ys,
            rprime=rprime,
            statement=statement,
        )

    def bind_public_values(
        self, issuer_key: IssuerPublicKey, tag: BlindMACTag, request: IssuanceRequest
    ):
        self.C_W.bind(RistrettoPoint(issuer_key.C_W))
        self.G_w.bind(RistrettoPoint(issuer_key.system.G_w))
        self.G_wprime.bind(RistrettoPoint(issuer_key.system.G_wprime))
        self.G_V_div_I.bind(RistrettoPoint(issuer_key.system.G_V - issuer_key.I))
        self.G_x0.bind(RistrettoPoint(issuer_key.system.G_x0))
        self.G_x1.bind(RistrettoPoint(issuer_key.system.G_x1))
        for G_y, G_y_value in zip(self.G_ys, issuer_key.system.G_ys):
            G_y.bind(RistrettoPoint(G_y_value))
        self.S1.bind(RistrettoPoint(tag.S.c1))
        for C1, C_value in zip(self.C1s, request.blinded_attributes):
            C1.bind(RistrettoPoint(C_value.c1))
        self.G.bind(RistrettoPoint(issuer_key.system.G))
        self.S2.bind(RistrettoPoint(tag.S.c2))
        for C2, C_value in zip(self.C2s, request.blinded_attributes):
            C2.bind(RistrettoPoint(C_value.c2))
        self.Y.bind(RistrettoPoint(request.blinding_key.key))
        for M, M_value in zip(self.Ms, request.clear_attributes):
            M.bind(RistrettoPoint(M_value))
        self.U.bind(RistrettoPoint(tag.U))
        self.U_raised_to_t.bind(RistrettoPoint(tag.U) ** RistrettoScalar(tag.t))

    def bind_secret_values(
        self, issuer_key: IssuerKeyPair, encryption_secret_nonce: RistrettoScalar
    ):
        self.w.bind(RistrettoScalar(issuer_key.secret.w))
        self.wprime.bind(RistrettoScalar(issuer_key.secret.wprime))
        self.x0.bind(RistrettoScalar(issuer_key.secret.x0))
        self.x1.bind(RistrettoScalar(issuer_key.secret.x1))
        for y, y_value in zip(self.ys, issuer_key.secret.ys):
            y.bind(RistrettoScalar(y_value))
        self.rprime.bind(RistrettoScalar(encryption_secret_nonce))

    def prove(self) -> Proof:
        return self.statement.prove()

    def verify(self, proof: Proof) -> bool:
        return self.statement.verify(proof)
