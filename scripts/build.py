#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml

if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

ROOT = Path(__file__).resolve().parents[1]
CACHE_DIR = ROOT / ".cache"
OUTPUT_DIR = ROOT / "ruleset"
DEFAULT_CONFIG = ROOT / "config" / "rulesets.yaml"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?$"
)


@dataclass(frozen=True, order=True)
class Rule:
    kind: str
    value: str


# --------------------------- parsing / normalize ---------------------------

def die(msg: str) -> None:
    raise SystemExit(f"ERROR: {msg}")


def normalize_domain(value: str) -> str | None:
    s = value.strip().strip('"\'').rstrip(".").lower()
    if not s:
        return None
    if s.startswith("||"):
        s = s[2:]
    if s.startswith("+."):
        s = s[2:]
    elif s.startswith("."):
        s = s[1:]
    elif s.startswith("*."):
        s = s[2:]
    if not DOMAIN_RE.match(s):
        return None
    return s


def normalize_cidr(value: str) -> str | None:
    s = value.strip().strip('"\'')
    if not s:
        return None
    try:
        if "/" not in s:
            addr = ipaddress.ip_address(s)
            return f"{addr}/{32 if addr.version == 4 else 128}"
        return str(ipaddress.ip_network(s, strict=False))
    except ValueError:
        return None


def parse_rule_line(line: str, behavior: str) -> Rule | None:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith(";"):
        return None
    if "#" in line:
        line = line.split("#", 1)[0].strip()
    if not line:
        return None

    if "," in line:
        kind, rest = line.split(",", 1)
        kind = kind.strip().upper()
        value = rest.split(",", 1)[0].strip()
        if behavior == "domain" and kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
            normalized = normalize_domain(value)
            return Rule(kind, normalized) if normalized else None
        if behavior == "ipcidr" and kind in {"IP-CIDR", "IP-CIDR6"}:
            normalized = normalize_cidr(value)
            return Rule(kind, normalized) if normalized else None
        return None

    if behavior == "domain":
        # Mihomo domain text/YAML uses bare domain for exact match and +.domain for suffix match.
        normalized = normalize_domain(line)
        if normalized:
            kind = "DOMAIN-SUFFIX" if line.startswith("+.") else "DOMAIN"
            return Rule(kind, normalized)
        return None

    if behavior == "ipcidr":
        normalized = normalize_cidr(line)
        if not normalized:
            return None
        return Rule("IP-CIDR6" if ":" in normalized else "IP-CIDR", normalized)

    return None


def parse_rule_value(line: str, behavior: str) -> str | None:
    rule = parse_rule_line(line, behavior)
    return rule.value if rule else None


def parse_text(text: str, behavior: str) -> set[Rule]:
    values: set[Rule] = set()
    for line in text.splitlines():
        rule = parse_rule_line(line, behavior)
        if rule:
            values.add(rule)
    return values


def parse_yaml_text(text: str, behavior: str) -> set[Rule]:
    try:
        obj = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        die(f"invalid YAML: {exc}")
    if not isinstance(obj, dict):
        return set()
    payload = obj.get("payload", [])
    if not isinstance(payload, list):
        return set()
    values: set[Rule] = set()
    for item in payload:
        if isinstance(item, str):
            rule = parse_rule_line(item, behavior)
            if rule:
                values.add(rule)
    return values


def parse_inline(source: dict, behavior: str) -> set[Rule]:
    values = source.get("inline", [])
    if not isinstance(values, list):
        die("inline source must be a list")
    result: set[Rule] = set()
    for item in values:
        if not isinstance(item, str):
            continue
        rule = parse_rule_line(item, behavior)
        if rule:
            result.add(rule)
    return result


# --------------------------------- fetch ----------------------------------

def fetch(url: str) -> bytes:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(url.encode()).hexdigest()
    cache_file = CACHE_DIR / key
    req = Request(url, headers={"User-Agent": "ruleset-builder/0.3"})
    try:
        with urlopen(req, timeout=60) as resp:
            data = resp.read()
        cache_file.write_bytes(data)
        return data
    except (HTTPError, URLError, TimeoutError) as exc:
        if cache_file.exists():
            print(f"  ! fetch failed, using cache: {url}", file=sys.stderr)
            return cache_file.read_bytes()
        raise RuntimeError(f"failed to download {url}: {exc}") from exc


def detect_type(source: dict) -> str:
    if source.get("inline") is not None:
        return "inline"
    if source.get("format"):
        return str(source["format"]).lower()
    # Backward compatibility with the previous config schema.
    if source.get("type"):
        return str(source["type"]).lower()
    url = str(source.get("url", "")).lower().split("?", 1)[0]
    if url.endswith(".mrs"):
        return "mrs"
    if url.endswith(".srs"):
        return "srs"
    if url.endswith(".yaml") or url.endswith(".yml"):
        return "yaml"
    return "list"


# ------------------------------- MRS bridge -------------------------------

def convert_mrs_to_text(data: bytes, mihomo: str, behavior: str) -> str:
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "source.mrs"
        dst = Path(td) / "source.txt"
        src.write_bytes(data)
        cmd = [mihomo, "convert-ruleset", behavior, "mrs", str(src), str(dst)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            die(f"mihomo MRS decode failed: {result.stderr.strip() or result.stdout.strip()}")
        return dst.read_text(encoding="utf-8")

def convert_srs_to_text(data: bytes, singbox: str, behavior: str) -> str:
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "source.srs"
        dst = Path(td) / "source.json"
        src.write_bytes(data)
        cmd = [singbox, "rule-set", "decompile", str(src), "-o", str(dst)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            die(f"sing-box SRS decode failed: {result.stderr.strip() or result.stdout.strip()}")
        obj = json.loads(dst.read_text(encoding="utf-8"))
        lines: list[str] = []
        for r in obj.get("rules", []):
            if behavior == "domain":
                for d in r.get("domain", []):
                    lines.append(f"DOMAIN,{d}")
                for s in r.get("domain_suffix", []):
                    lines.append(f"DOMAIN-SUFFIX,{s}")
            elif behavior == "ipcidr":
                for c in r.get("ip_cidr", []):
                    lines.append(f"IP-CIDR,{c}")
        return "\n".join(lines) + ("\n" if lines else "")


# ---------------------------- source collection ---------------------------

def load_source(
    source: dict,
    behavior: str,
    mihomo: str,
    singbox: str,
    collections: dict,
    collection_cache: dict[str, set[Rule]],
) -> set[Rule]:
    if "ref" in source:
        ref = str(source["ref"])
        if ref not in collections:
            die(f"unknown collection: {ref}")
        if ref not in collection_cache:
            collection_cache[ref] = load_source(collections[ref], behavior, mihomo, singbox, collections, collection_cache)
        return set(collection_cache[ref])

    typ = detect_type(source)
    if typ == "inline":
        return parse_inline(source, behavior)

    url = source.get("url")
    if not url:
        die("source requires url, ref, or inline")
    print(f"  + collect [{typ}] {url}")
    data = fetch(str(url))
    if typ in {"list", "text"}:
        return parse_text(data.decode("utf-8-sig", errors="replace"), behavior)
    if typ == "yaml":
        return parse_yaml_text(data.decode("utf-8-sig", errors="replace"), behavior)
    if typ == "mrs":
        return parse_text(convert_mrs_to_text(data, mihomo, behavior), behavior)
    if typ == "srs":
        return parse_text(convert_srs_to_text(data, singbox, behavior), behavior)
    die(f"unsupported source type: {typ}")
    return set()


# -------------------------------- excludes --------------------------------

def domain_covers(rule: Rule, exclude: Rule) -> bool:
    """Whether exclude removes the entire match set represented by rule."""
    if exclude.kind not in {"DOMAIN", "DOMAIN-SUFFIX"}:
        return False
    if rule.kind == "DOMAIN":
        if exclude.kind == "DOMAIN":
            return rule.value == exclude.value
        return parent_or_same(rule.value, exclude.value)
    # A DOMAIN-SUFFIX rule is only fully removable by another suffix that covers it.
    if rule.kind == "DOMAIN-SUFFIX":
        return exclude.kind == "DOMAIN-SUFFIX" and parent_or_same(rule.value, exclude.value)
    return False


def parent_or_same(value: str, parent: str) -> bool:
    return value == parent or value.endswith("." + parent)


def apply_domain_excludes(values: set[Rule], excludes: set[Rule]) -> tuple[set[Rule], int]:
    kept = {
        rule
        for rule in values
        if not any(domain_covers(rule, ex) for ex in excludes)
    }
    return kept, len(values) - len(kept)


def cidr_intersects(a: ipaddress._BaseNetwork, b: ipaddress._BaseNetwork) -> bool:
    return a.version == b.version and a.overlaps(b)


def subtract_one_cidr(value: str, exclude: str) -> list[str]:
    a = ipaddress.ip_network(value, strict=False)
    b = ipaddress.ip_network(exclude, strict=False)

    if not cidr_intersects(a, b):
        return [str(a)]
    if a.subnet_of(b):
        return []
    if b.subnet_of(a):
        return [str(net) for net in a.address_exclude(b)]
    return [str(a)]


def apply_ipcidr_excludes(values: set[Rule], excludes: set[Rule]) -> tuple[set[Rule], int]:
    current = {rule.value for rule in values}
    before = len(current)
    for ex in excludes:
        next_values: set[str] = set()
        for value in current:
            next_values.update(subtract_one_cidr(value, ex.value))
        current = next_values
    result = {
        Rule("IP-CIDR6" if ":" in value else "IP-CIDR", value)
        for value in current
    }
    return result, before - len(result)


def apply_excludes(values: set[Rule], excludes: set[Rule], behavior: str) -> tuple[set[Rule], int]:
    if not excludes:
        return values, 0
    if behavior == "domain":
        return apply_domain_excludes(values, excludes)
    if behavior == "ipcidr":
        return apply_ipcidr_excludes(values, excludes)
    die(f"unsupported exclude behavior: {behavior}")
    return values, 0


# ---------------------------------- output ---------------------------------

def render_domain(rule: Rule) -> str:
    if rule.kind == "DOMAIN-SUFFIX":
        return f"+.{rule.value}"
    return f"DOMAIN,{rule.value}"


def render_ip(rule: Rule) -> str:
    return f"{rule.kind},{rule.value}"


def write_list(values: set[Rule], path: Path, behavior: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if behavior == "domain":
        lines = [render_domain(rule) for rule in sorted(values)]
    else:
        lines = [render_ip(rule) for rule in sorted(values)]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def write_yaml(values: set[Rule], path: Path, behavior: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if behavior == "domain":
        payload = [render_domain(rule) for rule in sorted(values)]
    else:
        payload = [render_ip(rule) for rule in sorted(values)]
    path.write_text(
        yaml.safe_dump({"payload": payload}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def compile_mrs(values: set[Rule], path: Path, mihomo: str, behavior: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        txt = Path(td) / "rules.txt"
        if behavior == "domain":
            # Mihomo's domain/text input is not classical syntax:
            # bare domain = exact, +.domain = suffix.
            lines = [
                rule.value if rule.kind == "DOMAIN" else f"+.{rule.value}"
                for rule in sorted(values)
            ]
        else:
            # ipcidr/text likewise expects plain CIDRs, not IP-CIDR prefixes.
            lines = [rule.value for rule in sorted(values)]
        txt.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        cmd = [mihomo, "convert-ruleset", behavior, "text", str(txt), str(path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            die(f"mihomo MRS compile failed for {path.name}: {result.stderr.strip() or result.stdout.strip()}")

def render_singbox_payload(values: set[Rule], behavior: str) -> dict:
    if behavior == "domain":
        domains: list[str] = []
        domain_suffixes: list[str] = []
        for rule in sorted(values):
            if rule.kind == "DOMAIN":
                domains.append(rule.value)
            elif rule.kind == "DOMAIN-SUFFIX":
                domain_suffixes.append(rule.value)
        headless_rule: dict[str, list[str]] = {}
        if domains:
            headless_rule["domain"] = domains
        if domain_suffixes:
            headless_rule["domain_suffix"] = domain_suffixes
        return {
            "version": 2,
            "rules": [headless_rule] if headless_rule else [],
        }
    if behavior == "ipcidr":
        cidrs = [rule.value for rule in sorted(values)]
        headless_rule = {}
        if cidrs:
            headless_rule["ip_cidr"] = cidrs
        return {
            "version": 2,
            "rules": [headless_rule] if headless_rule else [],
        }
    die(f"unsupported behavior for sing-box rule-set: {behavior}")
    return {}


def compile_srs(values: set[Rule], path: Path, singbox: str, behavior: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        src_json = Path(td) / "rule-set.json"
        payload = render_singbox_payload(values, behavior)
        src_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        cmd = [singbox, "rule-set", "compile", str(src_json), "-o", str(path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            die(f"sing-box SRS compile failed for {path.name}: {result.stderr.strip() or result.stdout.strip()}")


def normalize_outputs(raw: any) -> list[str]:
    if isinstance(raw, list):
        items = [str(x).strip().lower() for x in raw if str(x).strip()]
    else:
        items = [x.strip().lower() for x in str(raw).split(",") if x.strip()]
    if not items:
        die("output cannot be empty")
    for out in items:
        if out not in {"list", "yaml", "mrs", "srs"}:
            die(f"unsupported output format: {out}")
    return items


# --------------------------------- build ----------------------------------

def build_one(
    name: str,
    spec: dict,
    mihomo: str,
    singbox: str,
    collections: dict,
    collection_cache: dict[str, set[Rule]],
) -> None:
    behavior = str(spec.get("behavior", "domain")).lower()
    outputs = normalize_outputs(spec.get("output", ["mrs"]))
    if behavior not in {"domain", "ipcidr"}:
        die(f"{name}: behavior must be domain or ipcidr")

    print(f"\n==> {name} [{behavior} -> {', '.join(outputs)}]")
    merged: set[Rule] = set()
    sources = spec.get("sources", [])
    if not isinstance(sources, list) or not sources:
        die(f"{name}: sources must be a non-empty list")
    for source in sources:
        if not isinstance(source, dict):
            die(f"{name}: invalid source entry")
        merged.update(load_source(source, behavior, mihomo, singbox, collections, collection_cache))
    print(f"  = collected: {len(merged)} unique {behavior} rules")

    excludes: set[Rule] = set()
    for source in spec.get("exclude", []) or []:
        if not isinstance(source, dict):
            die(f"{name}: invalid exclude entry")
        excludes.update(load_source(source, behavior, mihomo, singbox, collections, collection_cache))
    if excludes:
        merged, removed = apply_excludes(merged, excludes, behavior)
        print(f"  - excluded: {removed} rules; remaining: {len(merged)}")

    for out_format in outputs:
        out = OUTPUT_DIR / f"{name}.{out_format}"
        if out_format == "list":
            write_list(merged, out, behavior)
        elif out_format == "yaml":
            write_yaml(merged, out, behavior)
        elif out_format == "mrs":
            compile_mrs(merged, out, mihomo, behavior)
        elif out_format == "srs":
            compile_srs(merged, out, singbox, behavior)
        print(f"  ✓ output: {out.relative_to(ROOT)} ({len(merged)} rules)")


def resolve_executable(name: str, fallback_candidates: list[Path]) -> str:
    if shutil.which(name):
        return name
    for cand in fallback_candidates:
        if cand.is_file():
            return str(cand)
    return name


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect, exclude, and compile Mihomo / sing-box rule sets")
    parser.add_argument("-c", "--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--mihomo", default=os.environ.get("MIHOMO", "mihomo"))
    parser.add_argument("--singbox", default=os.environ.get("SING_BOX", "sing-box"))
    parser.add_argument("--only", action="append", help="build only the named ruleset; repeatable")
    args = parser.parse_args()

    mihomo_bin = resolve_executable(
        args.mihomo,
        [
            ROOT / "mihomo-windows-amd64-v3.exe",
            ROOT / "mihomo.exe",
            ROOT / "mihomo",
        ],
    )

    singbox_bin = resolve_executable(
        args.singbox,
        [
            ROOT / "sing-box.exe",
            ROOT / "sing-box",
            ROOT.parent / "proxy-configuration" / "sb115" / "sing-box-1.15.0-alpha.12-windows-amd64" / "sing-box.exe",
        ],
    )

    with args.config.open("r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    collections = config.get("collections", {})
    if not isinstance(collections, dict):
        die("config.collections must be a mapping")

    rulesets = config.get("rulesets")
    if not isinstance(rulesets, dict):
        die("config.rulesets must be a mapping")

    collection_cache: dict[str, set[Rule]] = {}
    selected = args.only or list(rulesets.keys())
    for name in selected:
        if name not in rulesets:
            die(f"unknown ruleset: {name}")
        if not isinstance(rulesets[name], dict):
            die(f"ruleset {name} must be a mapping")
        build_one(name, rulesets[name], mihomo_bin, singbox_bin, collections, collection_cache)


if __name__ == "__main__":
    main()
