"""stripii -- strip personal data out of health and financial documents before
they reach an AI tool.

Everything runs locally. There is no network call, no telemetry and no model
download in the default install.

    from stripii import Scrubber, get_profile

    scrubber = Scrubber(get_profile("health"))
    result, vault = scrubber.scrub(report_text)
    redacted = result.text            # safe to paste
    answer = Scrubber.restore(reply, vault)   # put the real names back

For a file -- a PDF, a scan, a photo -- with a grade measured on the output:

    from stripii import redact_file

    result = redact_file("report.pdf", profile="health", outputs=("text", "pdf"))
    result.grade, result.outputs["pdf"]
"""

from __future__ import annotations

from .document import RedactionResult, Spot, redact_boxes, redact_file, scrub_text
from .engine import Scrubber, default_recognizers, resolve_overlaps
from .policy import PROFILES, Policy, get_profile
from .types import Action, Detection, Replacement, ScrubResult
from .vault import Vault, VaultError

__version__ = "0.3.0"

__all__ = [
    "PROFILES",
    "Action",
    "Detection",
    "Policy",
    "RedactionResult",
    "Replacement",
    "ScrubResult",
    "Scrubber",
    "Spot",
    "Vault",
    "VaultError",
    "__version__",
    "default_recognizers",
    "get_profile",
    "redact_boxes",
    "redact_file",
    "resolve_overlaps",
    "scrub_text",
]
