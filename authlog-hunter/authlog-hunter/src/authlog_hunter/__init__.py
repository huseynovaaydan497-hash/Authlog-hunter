"""authlog-hunter: detect SSH brute force, credential compromise and
post-exploitation activity in Linux authentication logs."""

__version__ = "0.1.0"

from .detectors import AnalysisResult, DetectionConfig, analyze
from .models import Event, EventType, Finding, Severity
from .parser import LogParser

__all__ = [
    "__version__",
    "AnalysisResult",
    "DetectionConfig",
    "Event",
    "EventType",
    "Finding",
    "LogParser",
    "Severity",
    "analyze",
]
