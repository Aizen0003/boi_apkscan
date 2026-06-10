"""Static-analysis error types."""


class AnalyzerError(Exception):
    """Base class for static-analysis errors."""


class ToolUnavailable(AnalyzerError):
    """A required tool/library is not installed or not reachable.

    Callers catch this and record an ``AnalysisGap`` instead of failing the run.
    """


class MobSFUnavailable(ToolUnavailable):
    """MobSF service is unreachable or returned a transport-level error."""


class MobSFVersionError(AnalyzerError):
    """MobSF is older than the enforced minimum patched version."""
