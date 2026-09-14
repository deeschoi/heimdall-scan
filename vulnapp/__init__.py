"""oedipus-vulnapp — a deliberately vulnerable multi-tenant API + UI.

This is Oedipus' *own* target. Unlike the vendored third-party benchmarks
(VAmPI, crAPI), every bug here is planted on purpose and mapped 1:1 to an
Oedipus check's oracle, so `oedipus eval vulnapp` has frozen ground truth.

Two build modes, selected by the ``VULNAPP_SAFE`` env var:

* ``VULNAPP_SAFE`` unset / "0"  -> vulnerable build   (the scored target)
* ``VULNAPP_SAFE=1``            -> hardened build      (false-positive control)

The hardened build fixes every planted bug, so a correct scanner must find
**zero** findings against it. That symmetry is what turns "high detection"
into a measured precision/recall number instead of a claim.
"""

__all__ = ["create_app"]

from vulnapp.app import create_app
