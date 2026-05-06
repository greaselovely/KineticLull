"""Bot/crawler User-Agent classification.

Backed by the vendored monperrus/crawler-user-agents JSON. Patterns are
loaded once at import. Operators refresh the JSON via the settings page;
the new list takes effect on the next worker restart (matches the rest
of the project's "restart to apply" UX).
"""

import json
import re
from pathlib import Path


DATA_PATH = Path(__file__).parent / 'data' / 'crawler_user_agents.json'


def _derive_name(pattern):
    """Extract a human-friendly name from a regex pattern.

    Picks the longest alphanumeric-and-dash run, which catches the
    common case ('Googlebot\\/' -> 'Googlebot', 'AdsBot-Google([^-]|$)'
    -> 'AdsBot-Google'). Falls back to the raw pattern when nothing
    matches.
    """
    runs = re.findall(r'[A-Za-z0-9_-]+', pattern)
    return max(runs, key=len) if runs else pattern


def _load_patterns():
    try:
        with DATA_PATH.open() as f:
            entries = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    compiled = []
    for entry in entries:
        pat = entry.get('pattern', '')
        if not pat:
            continue
        try:
            rx = re.compile(pat, re.IGNORECASE)
        except re.error:
            continue
        compiled.append((rx, _derive_name(pat)))
    return compiled


_PATTERNS = _load_patterns()


def pattern_count():
    return len(_PATTERNS)


def is_bot(ua):
    if not ua:
        return False
    for rx, _ in _PATTERNS:
        if rx.search(ua):
            return True
    return False


def bot_name(ua):
    """Return the friendly name of the first matching bot pattern, else None."""
    if not ua:
        return None
    for rx, name in _PATTERNS:
        if rx.search(ua):
            return name
    return None
