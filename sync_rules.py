"""Convert a single upstream revision to Clash/Mihomo rule-provider files."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.client import HTTPException
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen


UPSTREAM = "GMOogway/shadowrocket-rules"
UPSTREAM_URL = f"https://github.com/{UPSTREAM}"
POLICIES = ("PROXY", "REJECT", "DIRECT")
OUTPUTS = {
    "PROXY": {"domains": "proxy-domains.txt", "patterns": "proxy-patterns.txt", "networks": "proxy-ips.txt"},
    "REJECT": {"domains": "reject-domains.txt"},
    "DIRECT": {"domains": "direct-domains.txt", "patterns": "direct-patterns.txt"},
}
RULES_DIR = Path(__file__).resolve().parent / "rules"
MAX_DOWNLOAD = 32 * 1024 * 1024
URL_PREFIX = r"^https?:\/\/"


@dataclass
class Module:
    domains: set = field(default_factory=set)
    patterns: set = field(default_factory=set)
    networks: set = field(default_factory=set)
    skipped: dict = field(default_factory=dict)
    repaired: int = 0


def download(url, token=None):
    request = Request(url, headers={"User-Agent": "shadowrocket-clash-rules"})
    if token:
        request.add_unredirected_header("Authorization", f"Bearer {token}")
    for attempt in range(3):
        try:
            with urlopen(request, timeout=20) as response:
                data = response.read(MAX_DOWNLOAD + 1)
            if len(data) > MAX_DOWNLOAD:
                raise ValueError(f"Download exceeds {MAX_DOWNLOAD} bytes: {url}")
            return data.decode("utf-8-sig")
        except (URLError, TimeoutError, HTTPException):
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)


def upstream_revision():
    api = f"https://api.github.com/repos/{UPSTREAM}/git/ref/heads/master"
    response = json.loads(download(api, os.environ.get("GITHUB_TOKEN")))
    revision = response["object"]["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Upstream ref did not return a commit SHA")
    return revision


def download_module(revision, policy):
    name = f"sr_{policy.lower()}_list.module"
    raw = f"https://raw.githubusercontent.com/{UPSTREAM}/{revision}/{name}"
    try:
        return download(raw)
    except (URLError, TimeoutError, HTTPException):
        return download(f"https://cdn.jsdelivr.net/gh/{UPSTREAM}@{revision}/{name}")


def expand_range(match):
    atom, minimum, maximum = match.groups()
    minimum, maximum = int(minimum), int(maximum)
    if not 0 <= minimum <= maximum <= 64:
        raise ValueError("Unsupported range in URL-REGEX")
    required = f"{atom}{{{minimum}}}" if minimum else ""
    return "(?:" + required + (atom + "?") * (maximum - minimum) + ")"


def host_regex(pattern):
    if not pattern.startswith(URL_PREFIX) or not pattern.endswith(".*$"):
        return None
    host = pattern[len(URL_PREFIX):-3]
    if not host or "/" in host:
        return None
    host = host.replace(r"(.*\.)?", r"(?:[^.]+\.)*")
    host = host.replace(r"(.+\.)*", r"(?:[^.]+\.)*")
    host = host.replace(r"\S+", r"[a-z0-9._-]+").replace(".+", "[a-z0-9._-]+")
    # Classical text is comma-delimited. Expand bounded repetitions without commas.
    host = re.sub(r"(\[[^\]]+\])\{(\d+),(\d+)\}", expand_range, host)
    if "," in host:
        raise ValueError("URL-REGEX contains an unhandled comma")
    result = f"(?i)^{host}$"
    re.compile(result)
    return result


def add_rule(module, line, policy):
    body, target = line.rsplit(",", 1)
    if target != policy:
        raise ValueError(f"Expected routing target {policy}, got {target}")
    kind, value = body.split(",", 1)

    if kind == "DOMAIN-SUFFIX" and value.startswith("IP-CIDR,"):
        kind, value = value.split(",", 1)
        module.repaired += 1
    elif kind == "DOMAIN-SUFFIX" and value.startswith("OMAIN-SUFFIX,"):
        value = value.split(",", 1)[1]
        module.repaired += 1

    if kind in ("DOMAIN", "DOMAIN-SUFFIX"):
        if not re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*", value, re.IGNORECASE | re.ASCII):
            raise ValueError("Invalid domain")
        prefix = "+." if kind == "DOMAIN-SUFFIX" else ""
        module.domains.add(prefix + value.lower())
    elif kind == "DOMAIN-KEYWORD":
        if not value or "," in value:
            raise ValueError("Invalid domain keyword")
        module.patterns.add(f"{kind},{value}")
    elif kind == "URL-REGEX":
        if not (value.startswith('"') and value.endswith('"')):
            raise ValueError("URL-REGEX must be quoted")
        regex = host_regex(value[1:-1])
        if regex is None:
            module.skipped[kind] = module.skipped.get(kind, 0) + 1
        else:
            module.patterns.add(f"DOMAIN-REGEX,{regex}")
    elif kind in ("IP-CIDR", "IP-CIDR6"):
        network_type = ipaddress.IPv6Network if kind == "IP-CIDR6" else ipaddress.IPv4Network
        address, *flags = value.split(",")
        if flags not in ([], ["no-resolve"]):
            raise ValueError("Unknown IP rule flag")
        module.networks.add(",".join((kind, str(network_type(address)), *flags)))
    elif kind == "USER-AGENT":
        module.skipped[kind] = module.skipped.get(kind, 0) + 1
    else:
        raise ValueError(f"Unknown rule type {kind}")


def parse_module(text, policy):
    module = Module()
    declared = re.search(r"^#!desc=Rules:(\d+)\b", text, re.MULTILINE)
    in_rules = False
    count = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_rules = line.lower() == "[rule]"
        elif in_rules:
            count += 1
            try:
                add_rule(module, line, policy)
            except (ValueError, re.error) as error:
                raise ValueError(f"{policy} module line {number}: {error}") from error

    if not declared or count != int(declared[1]) or not module.domains:
        expected = declared[1] if declared else "missing"
        raise ValueError(f"{policy} module count mismatch or empty domain set (read {count}, expected {expected})")
    return module


def render_outputs(modules):
    outputs = {}
    for policy, module in modules.items():
        paths = OUTPUTS[policy]
        for category in ("domains", "patterns", "networks"):
            rules = getattr(module, category)
            if category not in paths:
                if rules:
                    raise ValueError(f"Unexpected {category} rules in {policy} module")
                continue
            filename = paths[category]
            header = f"# Generated from {UPSTREAM_URL}/blob/master/sr_{policy.lower()}_list.module\n"
            outputs[filename] = header + "".join(f"{rule}\n" for rule in sorted(rules))
            print(f"{filename}: {len(rules):,} rules")
        if module.repaired or module.skipped:
            print(f"{policy}: repaired {module.repaired}; skipped {module.skipped}")
    return outputs


def main():
    revision = upstream_revision()
    print(f"Upstream revision: {revision}", flush=True)
    with ThreadPoolExecutor(max_workers=len(POLICIES)) as pool:
        sources = pool.map(lambda policy: download_module(revision, policy), POLICIES)
        modules = {policy: parse_module(source, policy) for policy, source in zip(POLICIES, sources)}
    outputs = render_outputs(modules)
    RULES_DIR.mkdir(exist_ok=True)
    for name, content in outputs.items():
        (RULES_DIR / name).write_text(content, encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, HTTPException) as error:
        sys.exit(f"Sync failed: {error}")
