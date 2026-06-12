from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any
from uuid import uuid4

from sca_cli.core.subprocess_runner import run_tool, which
from sca_cli.normalize.findings import Component
from sca_cli.scanners.base import ScanContext
from sca_cli.utils.hashing import stable_hash
from sca_cli.utils.json import read_json, write_json


def generate_sbom(context: ScanContext) -> tuple[list[Component], Path, bool]:
    output = context.workspace.sbom / f"{context.scan_id}.cyclonedx.json"
    syft_cmd = context.config["external_tools"].get("syft", "syft")
    root = context.target_dir

    # Extract package metadata from manifest files in the scanned target
    pkg_meta = _extract_package_metadata(root)

    if which(syft_cmd):
        result = run_tool([syft_cmd, str(root), "-o", f"cyclonedx-json={output}"])
        if result.returncode == 0 and output.exists():
            try:
                raw_cyclonedx = read_json(output)
                # Parse Syft's components
                syft_components = _components_from_cyclonedx(raw_cyclonedx)
                # Merge with lightweight + code-analyzer extras
                # (This also runs scan_code_dependencies via collect_lightweight_components)
                lightweight = collect_lightweight_components(root)
                merged = _merge_components(syft_components, lightweight)
                extras = len(merged) - len(syft_components)
                if extras > 0:
                    context.warnings.append(
                        f"Lightweight parser + code analyzer found {extras} additional "
                        f"component(s) not detected by Syft"
                    )
                # Enrich Syft's output with full metadata + extra components
                enriched = _enrich_from_syft(raw_cyclonedx, merged, root, pkg_meta)
                write_json(output, enriched)
                return merged, output, True
            except Exception as exc:
                context.warnings.append(f"Syft SBOM parse failed; using built-in fallback: {exc}")
        else:
            context.warnings.append(
                f"Syft failed; using built-in lightweight parser: {result.stderr.strip()}"
            )
    else:
        context.warnings.append(
            "Syft not found. Falling back to built-in dependency parser. "
            "SBOM completeness may be reduced."
        )

    # Fallback: build CycloneDX entirely from built-in parsers + code analyzer
    components = collect_lightweight_components(root)
    bom = _build_fresh_cdx(components, root, pkg_meta, context)
    write_json(output, bom)
    return components, output, False


def _merge_components(syft: list[Component], lightweight: list[Component]) -> list[Component]:
    """Merge Syft and lightweight components, preferring Syft's version when both
    report the same package (Syft resolves from lockfile, so its version is more precise)."""
    seen: dict[tuple[str, str], Component] = {}
    for c in syft:
        seen[(c.ecosystem, c.name.lower())] = c
    for c in lightweight:
        key = (c.ecosystem, c.name.lower())
        if key not in seen:
            seen[key] = c
    return sorted(seen.values(), key=lambda item: (item.ecosystem, item.name, item.version or ""))


def collect_lightweight_components(root: Path) -> list[Component]:
    components: dict[tuple[str, str, str | None], Component] = {}
    for component in _parse_requirements(root):
        components[(component.ecosystem, component.name.lower(), component.version)] = component
    for component in _parse_pyproject(root / "pyproject.toml"):
        components[(component.ecosystem, component.name.lower(), component.version)] = component
    for component in _parse_package_json(root / "package.json"):
        components[(component.ecosystem, component.name.lower(), component.version)] = component
    for component in _parse_package_lock(root / "package-lock.json"):
        components[(component.ecosystem, component.name.lower(), component.version)] = component
    # Code-level dependency analysis — scans require()/import statements
    # to catch dependencies not declared in manifest files. This ensures SBOM
    # completeness even when manifest files are missing or incomplete.
    from sca_cli.scanners.code_deps import scan_code_dependencies  # noqa: PLC0415
    for component in scan_code_dependencies(root):
        key = (component.ecosystem, component.name.lower(), None)
        if key not in components:
            components[key] = component
    # External system tool dependency detection — scans for CLI tools like
    # pg_dump, psql, gzip, etc. referenced in code, scripts, and docs.
    from sca_cli.scanners.code_deps import scan_external_system_deps  # noqa: PLC0415
    for component in scan_external_system_deps(root):
        key = ("external", component.name.lower(), None)
        if key not in components:
            components[key] = component
    return sorted(components.values(), key=lambda item: (item.ecosystem, item.name, item.version or ""))


def _parse_requirements(root: Path) -> list[Component]:
    components: list[Component] = []
    for path in root.rglob("requirements*.txt"):
        if "site-packages" in path.parts:
            continue
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-r", "--")):
                continue
            match = re.match(r"([A-Za-z0-9_.-]+)\s*(?:==|===|~=|>=|<=|>|<)?\s*([^;,\s]+)?", stripped)
            if not match:
                continue
            name, version = match.group(1), match.group(2)
            components.append(
                Component(
                    ecosystem="pypi",
                    name=name,
                    version=version if "://" not in (version or "") else None,
                    purl=_purl("pypi", name, version),
                    evidence=path.relative_to(root).as_posix(),
                    source="requirements",
                )
            )
    return components


def _parse_pyproject(path: Path) -> list[Component]:
    if not path.exists():
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    deps: list[str] = []
    deps.extend(data.get("project", {}).get("dependencies") or [])
    optional = data.get("project", {}).get("optional-dependencies") or {}
    for values in optional.values():
        deps.extend(values or [])
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies") or {}
    for name, version in poetry_deps.items():
        if name.lower() == "python":
            continue
        if isinstance(version, str):
            deps.append(f"{name}{version if version.startswith(('=', '<', '>', '~', '^')) else '==' + version}")
        else:
            deps.append(name)
    components: list[Component] = []
    for dep in deps:
        match = re.match(r"([A-Za-z0-9_.-]+)\s*(?:\[[^\]]+\])?\s*([<>=!~^].*)?", dep)
        if not match:
            continue
        name = match.group(1)
        version_spec = match.group(2) or None
        pinned = None
        if version_spec:
            pin = re.search(r"==\s*([A-Za-z0-9_.!+-]+)", version_spec)
            pinned = pin.group(1) if pin else version_spec.strip()
        components.append(Component(ecosystem="pypi", name=name, version=pinned, purl=_purl("pypi", name, pinned), evidence="pyproject.toml", source="pyproject"))
    return components


def _parse_package_json(path: Path) -> list[Component]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    components: list[Component] = []
    for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
        for name, version in (data.get(section) or {}).items():
            components.append(Component(ecosystem="npm", name=name, version=str(version), purl=_purl("npm", name, str(version)), evidence=f"package.json:{section}", source="package.json"))
    return components


def _parse_package_lock(path: Path) -> list[Component]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    components: list[Component] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for package_path, meta in packages.items():
            if not package_path.startswith("node_modules/"):
                continue
            name = package_path.removeprefix("node_modules/")
            version = str(meta.get("version") or "")
            components.append(Component(ecosystem="npm", name=name, version=version or None, purl=_purl("npm", name, version), evidence="package-lock.json", source="package-lock"))
    for name, meta in (data.get("dependencies") or {}).items():
        version = str(meta.get("version") or "")
        components.append(Component(ecosystem="npm", name=name, version=version or None, purl=_purl("npm", name, version), evidence="package-lock.json", source="package-lock"))
    return components


def _components_from_cyclonedx(data: dict[str, Any]) -> list[Component]:
    components: list[Component] = []
    for item in data.get("components") or []:
        purl = item.get("purl")
        ecosystem = _ecosystem_from_purl(purl) or item.get("type") or "unknown"
        components.append(
            Component(
                ecosystem=ecosystem,
                name=str(item.get("name") or ""),
                version=item.get("version"),
                purl=purl,
                type=item.get("type") or "library",
                source="syft",
                licenses=[lic.get("license", {}).get("id") for lic in item.get("licenses") or [] if isinstance(lic, dict) and lic.get("license")],
            )
        )
    return [component for component in components if component.name]


def _build_cyclonedx(context: ScanContext, components: list[Component]) -> dict[str, Any]:
    """Deprecated — use _enrich_from_syft() or _build_fresh_cdx() instead.
    Kept for backward compatibility."""
    pkg_meta = _extract_package_metadata(context.target_dir)
    return _build_fresh_cdx(components, context.target_dir, pkg_meta, context)


def _enrich_from_syft(
    raw: dict[str, Any],
    components: list[Component],
    root: Path,
    pkg_meta: dict[str, Any],
) -> dict[str, Any]:
    """Enrich a Syft-produced CycloneDX with full metadata and extra components."""
    bom = dict(raw)  # shallow copy — preserve Syft's structure

    # Ensure spec version is at least 1.5
    _upgrade_spec(bom)

    # Enrich metadata
    meta = dict(bom.get("metadata") or {})
    component_meta = dict(meta.get("component") or {})
    component_meta["type"] = "application"
    if pkg_meta.get("name"):
        component_meta["name"] = pkg_meta["name"]
    if pkg_meta.get("version"):
        component_meta["version"] = pkg_meta["version"]
    if pkg_meta.get("purl"):
        component_meta.setdefault("purl", pkg_meta["purl"])
    # Licenses
    if pkg_meta.get("licenses"):
        component_meta["licenses"] = pkg_meta["licenses"]
    meta["component"] = component_meta

    # manufacture / publisher
    if pkg_meta.get("publisher"):
        meta["manufacture"] = {"name": pkg_meta["publisher"]}
    if pkg_meta.get("supplier"):
        meta["supplier"] = {"name": pkg_meta["supplier"]}
    # Authors — CycloneDX standard field (since 1.4)
    if pkg_meta.get("author"):
        meta["authors"] = _parse_authors(pkg_meta["author"])

    # Properties (custom metadata)
    properties = list(meta.get("properties") or [])
    for prop in _pkg_meta_properties(pkg_meta):
        if prop not in properties:
            properties.append(prop)
    if properties:
        meta["properties"] = properties
    bom["metadata"] = meta

    # Merge components: keep Syft's entries, add any extras from our parsers
    syft_refs = {c.get("bom-ref") or c.get("purl") or c.get("name", ""): c for c in bom.get("components") or []}
    added_refs: set[str] = set()
    cdx_components = list(bom.get("components") or [])
    for c in components:
        ref = c.purl or f"pkg:{c.ecosystem}/{c.name}"
        if ref not in syft_refs and ref not in added_refs:
            added_refs.add(ref)
            cdx_components.append(_component_to_cdx(c))
    bom["components"] = cdx_components

    # Build / update dependency tree
    root_ref = _root_ref(pkg_meta)
    existing_deps_raw = {(d.get("ref") or ""): set(d.get("dependsOn") or []) for d in bom.get("dependencies") or []}

    # Add root → all deps
    root_depends: set[str] = set()
    for c in cdx_components:
        ref = c.get("bom-ref") or c.get("purl") or c.get("name", "")
        if ref and ref != root_ref:
            root_depends.add(ref)

    if root_ref in existing_deps_raw:
        existing_deps_raw[root_ref].update(root_depends)
    else:
        existing_deps_raw[root_ref] = root_depends

    # Ensure every component appears in the dependency tree (even if leaf nodes)
    for c in cdx_components:
        ref = c.get("bom-ref") or c.get("purl") or c.get("name", "")
        if ref and ref not in existing_deps_raw:
            existing_deps_raw[ref] = set()

    bom["dependencies"] = [
        {"ref": ref, "dependsOn": sorted(deps)}
        for ref, deps in sorted(existing_deps_raw.items())
    ]

    return bom


def _build_fresh_cdx(
    components: list[Component],
    root: Path,
    pkg_meta: dict[str, Any],
    context: ScanContext,
) -> dict[str, Any]:
    """Build a complete CycloneDX SBOM from scratch (fallback when Syft is unavailable)."""
    tool_name = "sca-cli"
    tool_version = "0.1.0"

    # Root component
    root_comp: dict[str, Any] = {"type": "application"}
    if pkg_meta.get("name"):
        root_comp["name"] = pkg_meta["name"]
    else:
        root_comp["name"] = context.options.get("project_name") or root.name
    if pkg_meta.get("version"):
        root_comp["version"] = pkg_meta["version"]
    if pkg_meta.get("purl"):
        root_comp["purl"] = pkg_meta["purl"]
    if pkg_meta.get("licenses"):
        root_comp["licenses"] = pkg_meta["licenses"]

    # Timestamp
    from sca_cli.utils.time import utc_now_iso  # noqa: PLC0415

    timestamp = utc_now_iso()

    root_ref = _root_ref(pkg_meta)

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4().hex}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": tool_name,
                        "version": tool_version,
                    },
                ],
            },
            "manufacture": {"name": pkg_meta.get("publisher") or "unknown"}
            if pkg_meta.get("publisher")
            else None,
            "authors": _parse_authors(pkg_meta.get("author"))
            if pkg_meta.get("author")
            else None,
            "component": root_comp,
            "properties": _pkg_meta_properties(pkg_meta),
        },
        "components": [_component_to_cdx(c) for c in components],
    }

    # Dependency tree
    root_depends = [
        c.purl or f"pkg:{c.ecosystem}/{c.name}" for c in components if c.purl or c.ecosystem
    ]
    dep_tree: list[dict[str, Any]] = [
        {"ref": root_ref, "dependsOn": root_depends},
    ]
    for c in components:
        c_ref = c.purl or f"pkg:{c.ecosystem}/{c.name}"
        # Leaf nodes have no further dependencies
        dep_tree.append({"ref": c_ref, "dependsOn": []})

    bom["dependencies"] = dep_tree

    # Remove None values from metadata
    bom["metadata"] = {k: v for k, v in bom["metadata"].items() if v is not None}

    return bom


def _purl(ecosystem: str, name: str, version: str | None) -> str | None:
    if not version:
        return f"pkg:{ecosystem}/{name}"
    if version.startswith(("<", ">", "=", "~", "^", "*")):
        return f"pkg:{ecosystem}/{name}"
    return f"pkg:{ecosystem}/{name}@{version}"


def _ecosystem_from_purl(purl: str | None) -> str | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    return purl.split("/", 1)[0].removeprefix("pkg:")


# ---------------------------------------------------------------------------
# New helper functions for full CycloneDX SBOM enrichment
# ---------------------------------------------------------------------------


def _extract_package_metadata(root: Path) -> dict[str, Any]:
    """Extract package metadata from manifest files found under *root*.

    Reads from:
      - package.json            → name, version, licenses, author
      - _meta.json              → ownerId, slug, publishedAt
      - skill-card.md / *.md    → publisher (from markdown Publisher: field)
    """
    meta: dict[str, Any] = {"_sources": []}

    # package.json
    pkg_json = root / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
            if data.get("name"):
                meta["name"] = data["name"]
            if data.get("version"):
                meta["version"] = data["version"]
            if data.get("license"):
                meta["licenses"] = _parse_license(data["license"])
            if data.get("author"):
                meta["author"] = data["author"]
            meta["_sources"].append("package.json")
        except Exception:
            pass

    # pyproject.toml (fallback for name/version)
    pyproj = root / "pyproject.toml"
    if pyproj.exists() and "name" not in meta:
        try:
            import tomllib  # noqa: PLC0415

            data = tomllib.loads(pyproj.read_text(encoding="utf-8", errors="replace"))
            proj = data.get("project") or {}
            if proj.get("name"):
                meta["name"] = proj["name"]
            if proj.get("version"):
                meta["version"] = proj["version"]
            if proj.get("license"):
                lic = proj["license"]
                if isinstance(lic, dict):
                    lic = _parse_license(lic.get("text") or lic.get("id") or "")
                elif isinstance(lic, str):
                    lic = _parse_license(lic)
                if lic:
                    meta["licenses"] = lic
            meta["_sources"].append("pyproject.toml")
        except Exception:
            pass

    # _meta.json (Hermes skill metadata)
    meta_json = root / "_meta.json"
    if meta_json.exists():
        try:
            data = json.loads(meta_json.read_text(encoding="utf-8", errors="replace"))
            if data.get("ownerId"):
                meta["ownerId"] = data["ownerId"]
            if data.get("slug"):
                meta["slug"] = data["slug"]
            if data.get("publishedAt"):
                meta["publishedAt"] = data["publishedAt"]
            meta["_sources"].append("_meta.json")
        except Exception:
            pass

    # skill-card.md — extract publisher name and release URL from markdown
    # Pattern: ## Publisher: <br>\n[username](url) <br>
    #           ## Reference(s): <br>\n- [ClawHub release page](url)
    skill_card = root / "skill-card.md"
    for md_path in [skill_card] if skill_card.exists() else []:
        try:
            text = md_path.read_text(encoding="utf-8", errors="replace")
            pub_match = re.search(r"##\s*Publisher:.*?\n\[([^\]]+)\]", text, re.DOTALL)
            if pub_match:
                meta["publisher"] = pub_match.group(1)
                meta["_sources"].append("skill-card.md")
            # Release URL from Reference(s) section
            ref_match = re.search(
                r"##\s*Reference\(s\)\s*:.*?\n-\s+\[[^\]]+\]\(([^)]+)\)",
                text, re.DOTALL,
            )
            if ref_match:
                meta["releaseUrl"] = ref_match.group(1).strip()
        except Exception:
            pass

    # Build PURL for the scanned package itself
    if meta.get("name") and meta.get("version"):
        meta["purl"] = _purl("npm" if "package.json" in meta.get("_sources", []) else "pypi",
                             meta["name"], meta["version"])

    return meta


def _parse_license(value: str | dict | list | None) -> list[dict[str, Any]] | None:
    """Normalize license value into CycloneDX license format."""
    if not value:
        return None
    if isinstance(value, str):
        lid = value.strip()
        if lid and lid.lower() not in {"", "none", "proprietary", "unknown"}:
            return [{"license": {"id": lid}}]
    if isinstance(value, dict):
        lid = value.get("id") or value.get("text") or ""
        if isinstance(lid, str) and lid.strip():
            return [{"license": {"id": lid.strip()}}]
    if isinstance(value, list):
        ids: list[str] = []
        for item in value:
            parsed = _parse_license(item)
            if parsed:
                ids.extend(p["license"]["id"] for p in parsed)
        if ids:
            return [{"license": {"id": i}} for i in ids]
    return None


def _component_to_cdx(c: Component) -> dict[str, Any]:
    """Convert a Component dataclass to a CycloneDX component JSON dict."""
    entry: dict[str, Any] = {
        "type": c.type or "library",
        "name": c.name,
    }
    if c.version:
        entry["version"] = c.version
    if c.purl:
        entry["purl"] = c.purl
    # Licenses: use detected or mark unknown
    if c.licenses:
        entry["licenses"] = [{"license": {"id": lic}} for lic in c.licenses if lic]
    else:
        entry["licenses"] = [{"license": {"id": "UNKNOWN"}}]
    # Evidence — CycloneDX standard format for how a component was discovered
    evidence: dict[str, Any] = {}
    if c.source:
        evidence["identity"] = {"field": c.source}
    if c.evidence:
        evidence["occurrences"] = [{"location": c.evidence}]
    if evidence:
        entry["evidence"] = evidence
    # Properties: ecosystem info
    props: list[dict[str, str]] = []
    if c.ecosystem:
        props.append({"name": "sca-cli:ecosystem", "value": c.ecosystem})
    if props:
        entry["properties"] = props
    return entry


def _pkg_meta_properties(pkg_meta: dict[str, Any]) -> list[dict[str, str]]:
    """Convert package metadata fields to CycloneDX properties list."""
    props: list[dict[str, str]] = []
    for key, prefix in [
        ("ownerId", "sca-cli:ownerId"),
        ("slug", "sca-cli:slug"),
        ("publishedAt", "sca-cli:publishedAt"),
        ("releaseUrl", "sca-cli:releaseUrl"),
    ]:
        if pkg_meta.get(key):
            props.append({"name": prefix, "value": str(pkg_meta[key])})
    # Sources
    if pkg_meta.get("_sources"):
        props.append({"name": "sca-cli:metadata-sources",
                       "value": ",".join(pkg_meta["_sources"])})
    if pkg_meta.get("purl"):
        props.append({"name": "sca-cli:root-purl", "value": pkg_meta["purl"]})
    return props


def _root_ref(pkg_meta: dict[str, Any]) -> str:
    """Return the bom-ref for the scanned package's root component."""
    if pkg_meta.get("purl"):
        return pkg_meta["purl"]
    if pkg_meta.get("name"):
        return f"pkg:npm/{pkg_meta['name']}@{pkg_meta.get('version') or 'latest'}"
    return "pkg:unknown/root"


def _parse_authors(value: str | dict | list) -> list[dict[str, str]]:
    """Parse author field into CycloneDX authors array.

    Accepts formats like:
      - "杜甫 <杜甫@openclaw.ai>"           (name <email>)
      - "name"                              (name only)
      - {"name": "...", "email": "..."}     (object)
    """
    if isinstance(value, dict):
        entry: dict[str, str] = {}
        if value.get("name"):
            entry["name"] = str(value["name"])
        if value.get("email"):
            entry["email"] = str(value["email"])
        return [entry] if entry else []

    if isinstance(value, list):
        authors: list[dict[str, str]] = []
        for item in value:
            authors.extend(_parse_authors(item))
        return authors

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return []
        match = re.match(r"^\s*(.+?)\s*<([^>]+)>\s*$", value)
        if match:
            return [{"name": match.group(1).strip(), "email": match.group(2).strip()}]
        return [{"name": value}]

    return []


def _upgrade_spec(bom: dict[str, Any]) -> None:
    """Ensure specVersion is at least 1.5."""
    current = bom.get("specVersion", "")
    try:
        major = int(str(current).split(".")[0])
        if major < 1:
            bom["specVersion"] = "1.5"
        elif major == 1:
            minor = int(str(current).split(".")[1]) if "." in str(current) else 0
            if minor < 5:
                bom["specVersion"] = "1.5"
    except (ValueError, IndexError):
        bom["specVersion"] = "1.5"


# ---------------------------------------------------------------------------
# Vulnerability enrichment — merges scan findings into CycloneDX SBOM
# ---------------------------------------------------------------------------


def _finding_to_vuln(finding: Any) -> dict[str, Any]:
    """Convert an sca-cli Finding to a CycloneDX vulnerability entry."""
    vuln: dict[str, Any] = {}

    # ID: CVE if available, otherwise use rule_id or title
    vuln_id = finding.vuln_id or finding.rule_id or finding.finding_id
    if vuln_id:
        vuln["id"] = vuln_id
    else:
        vuln["id"] = f"SCA-{stable_hash(finding.title)[:8]}"

    # Source
    if finding.vuln_id and str(finding.vuln_id).startswith("CVE-"):
        vuln["source"] = {
            "name": "NVD",
            "url": f"https://nvd.nist.gov/vuln/detail/{finding.vuln_id}",
        }
    elif finding.rule_id:
        vuln["source"] = {"name": finding.rule_id}
    else:
        vuln["source"] = {"name": finding.source or "sca-cli"}

    # Title & description
    if finding.title:
        vuln["title"] = finding.title
    desc_parts = [finding.description] if finding.description else []
    if finding.file_path:
        desc_parts.append(f"Location: {finding.file_path}"
                         + (f":{finding.line_number}" if finding.line_number else ""))
    if desc_parts:
        vuln["description"] = "\n\n".join(desc_parts)

    # Recommendation
    if finding.remediation:
        vuln["recommendation"] = finding.remediation

    # Severity / ratings (CVSS-like)
    severity = getattr(finding, "severity", "info") or "info"
    score_map = {"critical": (9.0, 10.0), "high": (7.0, 8.9),
                 "medium": (4.0, 6.9), "low": (0.1, 3.9), "info": (0.0, 0.0)}
    low, high = score_map.get(severity, (0.0, 0.0))
    vuln["ratings"] = [{
        "severity": severity,
        "score": high,
        "method": "CVSSv31",
    }]

    # CWEs
    cwe = getattr(finding, "cwe", None)
    if cwe:
        vuln["cwes"] = [{"id": cwe}]

    # Affected component
    if finding.component_name:
        affects_ref = _purl_for_component(finding.ecosystem, finding.component_name,
                                          finding.component_version)
        vuln["affects"] = [{"ref": affects_ref}]

    # Category as property
    category = getattr(finding, "category", None)
    if category:
        vuln["properties"] = [{"name": "sca-cli:category", "value": category}]

    return vuln


def enrich_sbom_with_vulns(sbom_path: Path, findings: list[Any]) -> Path:
    """Read a CycloneDX SBOM, append vulnerability entries from findings,
    and write back. Returns the path to the enriched SBOM."""
    if not sbom_path or not sbom_path.exists() or not findings:
        return sbom_path

    try:
        bom = json.loads(sbom_path.read_text(encoding="utf-8"))
    except Exception:
        return sbom_path

    # Ensure specVersion is 1.6+ (vulnerabilities field requires 1.6)
    _upgrade_spec(bom)

    # Convert findings to CycloneDX vulnerabilities
    vulns = [_finding_to_vuln(f) for f in findings if f]

    # Merge with existing vulnerabilities
    existing = list(bom.get("vulnerabilities") or [])
    existing_ids = {v.get("id") for v in existing if v.get("id")}
    for v in vulns:
        if v.get("id") not in existing_ids:
            existing.append(v)
            if v.get("id"):
                existing_ids.add(v["id"])

    if existing:
        bom["vulnerabilities"] = existing

    write_json(sbom_path, bom)
    return sbom_path


def _purl_for_component(ecosystem: str | None, name: str, version: str | None = None) -> str:
    """Build a PURL for a component, used in affects references."""
    eco = ecosystem or "unknown"
    if version:
        return f"pkg:{eco}/{name}@{version}"
    return f"pkg:{eco}/{name}"
