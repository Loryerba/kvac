class ZkGroupVerificationFailure(Exception):
    """Exception that is thrown if decryption fails"""


class DeserializationFailure(Exception):
    """Exception that is thrown if deserialization fails"""


class VerificationFailure(Exception):
    """Raised when the verification of a cryptographic proof fails."""


class CallNotAllowed(Exception):
    """Raised when KVAC methods are called in the wrong order."""
