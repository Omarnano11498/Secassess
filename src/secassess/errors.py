"""Exception hierarchy. All operator-facing errors derive from SecAssessError."""


class SecAssessError(Exception):
    """Base class for expected, operator-facing errors."""


class ConfigError(SecAssessError):
    """Invalid or missing configuration."""


class ScopeError(SecAssessError):
    """A target is malformed or outside the authorized scope."""


class ConfirmationError(SecAssessError):
    """Active checks were requested without valid operator confirmation."""


class ToolError(SecAssessError):
    """An external tool is missing, failed, timed out or returned unusable output."""
