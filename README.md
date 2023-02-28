# Keyed-Verification Anonymous Credentials

A python implementation for Algebraic MACs and generic KVACs supporting blinded attributes during issuance and 
hidden attributes during presentation.

## Disclaimer

This module was developed as part of the 2022/23 *Current Topics in Group Messaging* seminar at the
[Hasso-Plattner-Institute (HPI)](https://hpi.de) trying to reproduce the Signal Private Group system described
by the paper ["The Signal Private Group System and Anonymous Credentials Supporting Efficient Verifiable Encryption" by
Chase et al.](https://eprint.iacr.org/2019/1416.pdf) Therefore, it is supposed to solely fulfill academic purposes.
Note that the original goal of reaching full compatibility with the [libsignal Rust implementation](https://github.com/signalapp/libsignal)
was dropped in favour of implementing a more generic version of the KVACs (as some implementation details of libsignal 
prevented us from doing so).

**THE AUTHORS DO NOT ASSUME RESPONSIBILITY FOR THE CORRECTNESS OF THE PERFORMED CRYPTOGRAPHIC OPERATIONS.
THERE WAS NO REVIEW PERFORMED BY AN EXPERT.
DO NOT USE THIS PROJECT IN A PRODUCTION ENVIRONMENT.**

## Installation

This project can be installed in multiple ways:

`requirements.txt`: Add `git+https://github.com/hpicrypto/kvac.git@0.1.0#egg=kvac`.

`pip(env)`: Run `pip(env) install git+https://github.com/hpicrypto/kvac.git@0.1.0#egg=kvac`.

`poetry`: Run `poetry add git+https://github.com/hpicrypto/kvac.git@0.1.0`.

## Usage

To implement a credential with specific attributes, inherit from the KVAC class in [kvac.py](kvac/kvac.py)
and mark class variables as attributes:

```python
from kvac import KVAC, Attribute

class ExampleCredential(KVAC):
    normal_attribute = Attribute()
    blind_attribute = Attribute(blind=True)
    scalar_attribute = Attribute(scalar=True)
    hidden_attribute = Attribute(hidden=True)
```

On instances of the Credential class, the values of the attribute class variables are available as instance variable.

Note that all other classes mainly serve the purpose of enabling this KVAC interface to work.

Now assume we have a system context given, constructed as follows:
```python
from kvac import SystemParams, IssuerKeyPair

system_params = SystemParams.generate(max_number_of_attributes, system_label)
issuer_key_pair = IssuerKeyPair.generate(
    system_params,
    ExampleCredential.number_of_attribute_components()
)
issuer_public_key = issuer_key_pair.public
```

Then, the lifecycle of a KVAC is as follows:

1. The user creates an *inactive* credential populated with values for all credential attributes:
    ```python
    kvac = ExampleCredential(
        issuer_public_key=issuer_public_key,
        normal_attribute=...,
        another_normal_attribute=...,
        blind_attribute=...
    )
    ```

1. The user creates an issuance request using the inactive credential
    ```python
    request, blind_attribute_commitments = kvac.request()
    ```
    and sends both to the issuer.

1. The issuer creates an issuance response
    ```python
    response = ExampleCredential.issue(
        issuer_key=issuer_key_pair,
        request=request,
        commitment=blind_attribute_commitments
    )
    ```
    and sends the response to the user.

1. The user activates the KVAC using the response:
    ```python
    kvac.activate(response)
    ```

1. The user creates a presentation using his (now *active*) KVAC and a set of hiding keys for the 
hidden attributes:
    ```python   
    presentation = kvac.present(
        hiding_keys=hiding_keys
    )
    ```
    The hiding keys (only one for our `ExampleCredential`) were generated earlier as
    ```python
    from kvac import KeyPair as HidingKeyPair
   
    hiding_keys = [
        HidingKeyPair.derive_from(
            issuer_public_key.system.G_es,
            hiding_master_key,  # Should be a randomly chosen byte string
            b'hidden_attribute_label'
        )
    ]
    ```

1. Finally, the issuer can verify the presentation using his secret key:
    ```python
    Credential.verify_presentation(
        issuer_key=issuer_key_pair,
        presentation=presentation
    )
    ```

Please also take a look at the [KVAC tests](tests/test_kvac.py) (and the [commons](tests/common.py) used there)
to get a better grasp on how everything works together.

Note that all the cryptographic operations required for issuance and presentation (such as generating and verifying
Non-Interactive Zero-Knowledge Proofs, encrypting and decrypting values, and creating and veryifing commitments
on values) are performed **automatically** under the hood.

## Limitations

Currently, we only support messages with a length of exactly 16 bytes for hidden attributes.

Additionally, scalar attributes cannot be also hidden with the present implementation.

## Testing

```
PYTHONPATH+=":$PWD" pytest tests/
```
