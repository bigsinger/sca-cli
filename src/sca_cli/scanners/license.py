from __future__ import annotations

from sca_cli.scanners.base import ScanContext


def scan_licenses(context: ScanContext):
    context.warnings.append("License policy scanning is not enabled in this build; SBOM license fields are still reported when available.")
    return []
