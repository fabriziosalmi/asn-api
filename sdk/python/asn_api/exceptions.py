class AsnApiError(Exception):
    """Base class for exceptions in this module."""
    pass


class APIError(AsnApiError):
    """Exception raised for HTTP errors returned by the API."""
    def __init__(self, message: str, status_code: int = 0):
        super().__init__(message)
        self.status_code = status_code


class ConfigurationError(AsnApiError):
    """Exception raised for invalid client configuration."""
    pass


class AuthenticationError(AsnApiError):
    """Exception raised for authentication errors (401, 403)."""
    pass


class RateLimitError(AsnApiError):
    """Exception raised when the API rate limit is exceeded."""
    def __init__(self, message: str, retry_after=None):
        super().__init__(message)
        self.retry_after = retry_after


# Alias used by the client module.
RateLimitExceeded = RateLimitError


class NotFoundError(AsnApiError):
    """Exception raised when a resource is not found (404)."""
    pass


class ServerError(AsnApiError):
    """Exception raised when the API server encounters an error (500+)."""
    pass
