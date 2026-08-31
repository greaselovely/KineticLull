"""Palo Alto User-ID push over the PAN-OS XML API.

Public entrypoints: `push_user_id_mappings(mappings, firewall, timeout_minutes)`
and `test_connection(firewall)`. Both return `(success: bool, message: str)` and
update the firewall's status fields in-place. Caller is responsible for
`firewall.save()`.

Everything is scoped to one `Firewall` row. Push state lives there rather than
on the AppSettings singleton because one firewall can reject while another
accepts, and a single shared status field would flap between them.

Mappings are sent as one `uid-message` document containing many `<entry>`
elements, which is what lets a morning full of logins collapse into a single
request. The `timeout` attribute on a login entry is in **minutes**; the
0-2,592,000 second range documented elsewhere belongs to dynamic address
group registration, a different request type on the same endpoint.
"""

import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

import requests
from django.utils import timezone

REQUEST_TIMEOUT_SECONDS = 30
# PAN-OS rejects an over-long timeout outright rather than clamping it. 30 days
# is far past anything useful here and keeps a fat-fingered setting from being
# silently accepted as "effectively permanent".
MAX_TIMEOUT_MINUTES = 43200


class PanOSError(Exception):
    pass


def _record_failure(firewall, count: int, message: str) -> tuple[bool, str]:
    # last_push_at is deliberately not touched. It is the delivery watermark,
    # and a failure delivered nothing.
    firewall.last_push_status = 'failed'
    firewall.last_push_count = count
    firewall.last_push_error = message[:1000]
    return False, message


def _record_success(firewall, count: int) -> tuple[bool, str]:
    # last_push_at doubles as the delivery watermark, so it advances only on a
    # confirmed success. Moving it on failure would mark mappings delivered
    # that the firewall never received.
    firewall.last_push_at = timezone.now()
    firewall.last_push_status = 'success'
    firewall.last_push_count = count
    firewall.last_push_error = ''
    return True, f'Pushed {count} user-ID mapping{"" if count == 1 else "s"}.'


def build_uid_message(mappings, timeout_minutes: int) -> str:
    """Render mappings as a PAN-OS `uid-message` login document.

    `mappings` is any iterable of objects exposing `username` and
    `ip_address`. Values are XML-escaped: a Workspace username is attacker-
    influenced data as far as this function is concerned.
    """
    timeout = max(1, min(int(timeout_minutes), MAX_TIMEOUT_MINUTES))

    entries = ''.join(
        f'<entry name="{escape(str(m.username), {chr(34): "&quot;"})}" '
        f'ip="{escape(str(m.ip_address), {chr(34): "&quot;"})}" '
        f'timeout="{timeout}"/>'
        for m in mappings
    )
    return (
        '<uid-message>'
        '<version>1.0</version>'
        '<type>update</type>'
        f'<payload><login>{entries}</login></payload>'
        '</uid-message>'
    )


def _api_url(firewall) -> str:
    host = (firewall.address or '').strip()
    if not host:
        raise PanOSError('No firewall host configured.')
    if not host.startswith(('http://', 'https://')):
        host = f'https://{host}'
    return f'{host.rstrip("/")}/api/'


def _check_response(text: str) -> None:
    """Raise PanOSError unless PAN-OS reported success.

    PAN-OS answers a rejected request with HTTP 200 and an error inside the
    body, so the status code alone proves nothing.
    """
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise PanOSError(f'Unparseable response from firewall: {text[:200]}')

    if root.attrib.get('status') == 'success':
        return

    message = ' '.join(part.strip() for part in root.itertext() if part.strip())
    raise PanOSError(message or f'Firewall rejected the request: {text[:200]}')


def _post(firewall, params: dict, files=None) -> str:
    response = requests.post(
        _api_url(firewall),
        params=params,
        files=files,
        verify=firewall.verify_ssl,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    _check_response(response.text)
    return response.text


def push_user_id_mappings(mappings, firewall, timeout_minutes) -> tuple[bool, str]:
    """Send the active mapping set to one firewall.

    An empty batch is a no-op success so callers do not have to special-case a
    quiet interval, and so a quiet interval never overwrites the last real push
    status.

    `timeout_minutes` is passed in rather than read off the firewall: how long
    a mapping should live is a policy decision that applies everywhere, not a
    property of any one box.
    """
    mappings = list(mappings)
    if not mappings:
        return True, 'No mappings to push.'

    if not (firewall.api_key or '').strip():
        return _record_failure(firewall, len(mappings), 'No API key configured for this firewall.')

    document = build_uid_message(mappings, timeout_minutes)

    params = {'type': 'user-id', 'key': firewall.api_key}
    if (firewall.vsys or '').strip():
        params['vsys'] = firewall.vsys.strip()

    try:
        _post(firewall, params, files={'file': ('uid.xml', document, 'application/xml')})
    except PanOSError as e:
        return _record_failure(firewall, len(mappings), str(e))
    except requests.RequestException as e:
        return _record_failure(firewall, len(mappings), f'Could not reach the firewall: {e}')

    return _record_success(firewall, len(mappings))


def test_connection(firewall) -> tuple[bool, str]:
    """Verify host, credentials, and TLS settings without changing anything.

    Deliberately does not touch the push status fields: a connectivity probe
    should not make a healthy integration look like it just failed, or a
    failing one look like it recovered.
    """
    if not (firewall.api_key or '').strip():
        return False, 'No API key configured for this firewall.'

    params = {
        'type': 'op',
        'cmd': '<show><system><info></info></system></show>',
        'key': firewall.api_key,
    }

    try:
        text = _post(firewall, params)
    except PanOSError as e:
        return False, str(e)
    except requests.RequestException as e:
        return False, f'Could not reach the firewall: {e}'

    try:
        root = ET.fromstring(text)
        model = root.findtext('.//model') or 'unknown model'
        version = root.findtext('.//sw-version') or 'unknown version'
        hostname = root.findtext('.//hostname') or ''
        who = f'{hostname} ' if hostname else ''
        return True, f'Connected to {who}({model}, PAN-OS {version}).'
    except ET.ParseError:
        return True, 'Connected.'


def curl_equivalent(firewall) -> str:
    """The hand-run command that reproduces a push, for the UI to show.

    The API key is left as a placeholder rather than rendered: this string is
    displayed in a browser and pasted into tickets.
    """
    host = (firewall.address or '<firewall>').strip()
    if not host.startswith(('http://', 'https://')):
        host = f'https://{host}'
    insecure = '' if firewall.verify_ssl else ' -k'
    vsys = f'&vsys={firewall.vsys.strip()}' if (firewall.vsys or '').strip() else ''
    return (
        f'curl{insecure} -X POST "{host.rstrip("/")}/api/?type=user-id{vsys}" '
        f'-F key=$PANOS_API_KEY -F file=@uid.xml'
    )
