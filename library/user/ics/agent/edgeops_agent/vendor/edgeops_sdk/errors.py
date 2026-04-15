"""
Custom error classes for EdgeOps SDK
"""


class EdgeOpsError(Exception):
    """Base exception for all EdgeOps SDK errors"""

    def __init__(self, message: str, code: str = None, details: dict = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class EdgeOpsConnectionError(EdgeOpsError):
    """Raised when connection to EdgeOps Cloud fails"""

    def __init__(self, message: str, details: dict = None):
        super().__init__(message, "CONNECTION_ERROR", details)


class EdgeOpsAuthError(EdgeOpsError):
    """Raised when authentication fails"""

    def __init__(self, message: str, details: dict = None):
        super().__init__(message, "AUTH_ERROR", details)


class EdgeOpsProvisioningError(EdgeOpsError):
    """Raised when device provisioning fails"""

    def __init__(self, message: str, details: dict = None):
        super().__init__(message, "PROVISIONING_ERROR", details)
