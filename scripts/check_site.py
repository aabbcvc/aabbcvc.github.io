"""Check the rendered public IOC feed and its source links after Jekyll builds."""
import argparse
import json
from pathlib import Path
from urllib.parse import unquote, urlsplit


def check(destination):
    posts = json.loads((destination / "iocs.json").read_text(encoding="utf-8"))
    assert isinstance(posts, list), "Public IOC feed must be a JSON array"
    for post in posts:
        assert isinstance(post["indicators"], list), f"{post['title']}: indicators must be an array, including when empty"
        assert isinstance(post["tags"], list) and post["tags"], f"{post['title']}: missing tags"
        path = unquote(urlsplit(post["url"]).path).lstrip("/")
        source = destination / path / "index.html"
        assert source.is_file(), f"Missing source page: {post['url']}"
        assert 'id="iocs"' in source.read_text(encoding="utf-8"), f"Missing IOC anchor: {post['url']}"
    for page in ["research", "bulletins", "iocs"]:
        assert (destination / page / "index.html").is_file(), f"Missing {page} page"
    print(f"Verified public IOC JSON and source links for {len(posts)} publications.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", nargs="?", default="_site", type=Path)
    check(parser.parse_args().destination)
