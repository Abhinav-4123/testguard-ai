"""QA Testing Agent - AI-powered autonomous testing"""

__all__ = ["QAAgent", "BrowserController", "ReportGenerator"]


def __getattr__(name):
    if name == "QAAgent":
        from .agent import QAAgent
        return QAAgent
    if name == "BrowserController":
        from .browser import BrowserController
        return BrowserController
    if name == "ReportGenerator":
        from .reporter import ReportGenerator
        return ReportGenerator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
