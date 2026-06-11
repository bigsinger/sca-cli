from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

from sca_cli.core.subprocess_runner import run_tool, which
from sca_cli.normalize.findings import Component
from sca_cli.scanners.base import ScanContext
from sca_cli.utils.json import read_json, write_json


def generate_sbom(context: ScanContext) -> tuple[list[Component], Path, bool]:
    output = context.workspace.sbom / f"{context.scan_id}.cyclonedx.json"
    syft_cmd = context.config["external_tools"].get("syft", "syft")
    if which(syft_cmd):
        result = run_tool([syft_cmd, str(context.target_dir), "-o", f"cyclonedx-json={output}"])
        if result.returncode == 0 and output.exists():
            try:
                return _components_from_cyclonedx(read_json(output)), output, True
            except Exception as exc:
                context.warnings.append(f"Syft SBOM parse failed; using built-in fallback: {exc}")
        else:
            context.warnings.append(f"Syft failed; using built-in lightweight parser: {result.stderr.strip()}")
    else:
        context.warnings.append("Syft not found. Falling back to built-in lightweight dependency parser. SBOM completeness may be reduced.")

    components = collect_lightweight_components(context.target_dir)
    write_json(output, _build_cyclonedx(context, components))
    return components, output, False


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
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": context.options.get("project_name") or context.target_dir.name,
            },
            "properties": [{"name": "sca-cli:generator", "value": "built-in-lightweight-parser"}],
        },
        "components": [
            {
                "type": component.type,
                "name": component.name,
                "version": component.version,
                "purl": component.purl,
                "properties": [{"name": "sca-cli:evidence", "value": component.evidence or ""}],
            }
            for component in components
        ],
    }


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
