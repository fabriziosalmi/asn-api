class AsnApiError(Exception):
    """Base class for exceptions in this module."""
    pass

class AuthenticationError(AsnApiError):
    """Exception raised for authentication errors (401, 403)."""
    pass

class RateLimitError(AsnApiError):
    """Exception raised when the API rate limit is exceeded."""
    def __init__(self, message, retry_after=None):
        super().__init__(message)
        self.retry_after = retry_after

class NotFoundError(AsnApiError):
    """Exception raised when a resource is not found (404)."""
    pass

class ServerError(AsnApiError):
    """Exception raised when the API server encounters an error (500+)."""
    pass
