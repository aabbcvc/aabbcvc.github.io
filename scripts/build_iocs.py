"""Validate publication metadata and extract the canonical Markdown IOC tables.

Run before Jekyll. Only Jekyll's published posts are exposed by /iocs.json.
No network access or Jekyll custom plugin is needed for normal builds.
"""
import argparse
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[1]
HEADER = ["Indicator", "Type", "Context"]
TYPES = {"IPv4", "IPv6", "Domain", "Onion", "URL", "URL pattern", "IP:port",
         "SHA256", "SHA1", "MD5", "Hash fragment", "IP pattern", "Filename",
         "File path", "URI path", "Email", "Wallet", "String", "Command pattern",
         "Scheduled task", "Service", "Extension", "HTTP header", "Auth token",
         "Bot username", "Process name", "Workflow name", "Firewall rule", "Snapshot"}


def refang(value):
    value = value.replace("\\[", "[").replace("\\]", "]")
    value = value.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[@]", "@")
    return re.sub(r"^hxxp", "http", value, flags=re.I)


def cells(line):
    # Escaped pipes belong to the cell (including command patterns).
    return [x.strip().replace("\\|", "|") for x in re.split(r"(?<!\\)\|", line.strip().strip("|"))]


def plain(value):
    value = re.sub(r"\[([^\]]+)\]\(https?://[^)]+\)", r"\1", value)
    return value.replace("`", "").replace("**", "").replace("<br>", " ").strip()


def validate_value(value, kind):
    if kind in {"IPv4", "IPv6"}:
        if ipaddress.ip_address(value).version != int(kind[-1]):
            raise ValueError("IP version mismatch")
    elif kind in {"SHA256", "SHA1", "MD5"}:
        length = {"SHA256": 64, "SHA1": 40, "MD5": 32}[kind]
        if not re.fullmatch(r"[a-fA-F0-9]{%d}" % length, value):
            raise ValueError("Invalid hash length or characters")
    elif kind in {"Domain", "Onion"}:
        if not re.fullmatch(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}", value):
            raise ValueError("Invalid domain")
        if (kind == "Onion") != value.endswith(".onion"):
            raise ValueError("Onion type mismatch")
    elif kind == "URL":
        parsed = urlsplit(value if "://" in value else "https://" + value)
        if not parsed.hostname or parsed.scheme not in {"http", "https"} or re.search(r"[<>\s]", value):
            raise ValueError("Invalid URL; use URL pattern for placeholders")
    elif kind == "IP:port":
        host, port = value.rsplit(":", 1)
        ipaddress.ip_address(host.strip("[]"))
        if not 1 <= int(port) <= 65535:
            raise ValueError("Invalid port")


def extract(body, source="post"):
    records = []
    inside = False
    fenced = False
    headers = None
    sections = 0
    for number, line in enumerate(body.splitlines(), 1):
        if re.match(r"^\s*(`{3,}|~{3,})", line):
            fenced = not fenced
            continue
        if fenced:
            continue
        if re.match(r"^# ", line):
            raise ValueError(f"{source}:{number}: use H2 sections; the page supplies H1")
        if line == "## IOCs":
            inside = True
            sections += 1
            continue
        if re.match(r"^#{1,2} ", line):
            inside = False
        if not inside or not line.startswith("|"):
            headers = None
            continue
        row = cells(line)
        if all(re.fullmatch(r"[-: ]+", cell) for cell in row):
            continue
        if headers is None:
            if row != HEADER:
                raise ValueError(f"{source}:{number}: IOC table must use {HEADER}")
            headers = row
            continue
        if len(row) != len(HEADER):
            raise ValueError(f"{source}:{number}: expected three IOC cells")
        original, kind, context = map(plain, row)
        value = refang(original)
        if kind not in TYPES:
            raise ValueError(f"{source}:{number}: unknown IOC type: {kind}")
        if not context or not value:
            raise ValueError(f"{source}:{number}: missing IOC context/value")
        try:
            validate_value(value, kind)
        except ValueError as exc:
            raise ValueError(f"{source}:{number}: {value}: {exc}") from exc
        if kind in {"Domain", "Onion", "MD5", "SHA1", "SHA256"}:
            value = value.lower()
        records.append(dict(value=value, display=original, type=kind, context=context))
    if sections != 1:
        raise ValueError(f"{source}: expected exactly one '## IOCs' section")
    return records


def build(root=ROOT):
    taxonomy = yaml.safe_load((root / "_data/tags.yml").read_text(encoding="utf-8"))
    result = {}
    for path in sorted((root / "_posts").rglob("*.md")):
        _, front, body = path.read_text(encoding="utf-8").split("---", 2)
        meta = yaml.safe_load(front)
        for field in ("title", "description", "content_type", "tags", "categories"):
            if not meta.get(field):
                raise ValueError(f"{path.name}: missing {field}")
        if meta["content_type"] not in {"research", "bulletin"}:
            raise ValueError(f"{path.name}: invalid content_type")
        if not isinstance(meta["tags"], list) or len(meta["tags"]) != len(set(meta["tags"])):
            raise ValueError(f"{path.name}: tags must be a unique list")
        if set(meta["tags"]) - set(taxonomy):
            raise ValueError(f"{path.name}: unknown tags {set(meta['tags']) - set(taxonomy)}")
        if meta["content_type"] == "bulletin" and meta.get("header", {}).get("teaser"):
            raise ValueError(f"{path.name}: bulletins do not use teaser images")
        result[path.relative_to(root).as_posix()] = extract(body, path.name)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the committed index is stale")
    args = parser.parse_args()
    result = build()
    output = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    path = ROOT / "_data/iocs.json"
    if args.check:
        if not path.exists() or path.read_text(encoding="utf-8") != output:
            raise SystemExit("IOC index is stale. Run python scripts/build_iocs.py")
    else:
        path.write_text(output, encoding="utf-8")
    print(f"Validated {len(result)} publications; extracted {sum(map(len, result.values()))} IOC observations.")


if __name__ == "__main__":
    main()
