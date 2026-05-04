"""
Backblaze B2 uploader using the native B2 API via `requests`.

Files at or below 200 MB use the single-shot `b2_upload_file` flow.
Larger files use the `b2_start_large_file` / `b2_upload_part` /
`b2_finish_large_file` flow with chunks sized at the auth response's
`recommendedPartSize` (typically 100 MB).

Public entrypoint: `upload_file(local_path, app_settings)` returns
`(success: bool, message: str)` and updates the AppSettings status fields
in-place. Caller is responsible for `app_settings.save()`.
"""

import hashlib
from pathlib import Path

import requests
from django.utils import timezone

B2_AUTH_URL = 'https://api.backblazeb2.com/b2api/v3/b2_authorize_account'
SINGLE_SHOT_LIMIT_BYTES = 200 * 1024 * 1024


class B2Error(Exception):
    pass


def _sha1_of_file(path: Path) -> str:
    h = hashlib.sha1()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def _record_failure(app_settings, filename: str, message: str) -> tuple[bool, str]:
    app_settings.b2_last_upload_at = timezone.now()
    app_settings.b2_last_upload_status = 'failed'
    app_settings.b2_last_upload_filename = filename
    app_settings.b2_last_upload_error = message[:1000]
    return False, message


def _record_success(app_settings, filename: str) -> tuple[bool, str]:
    app_settings.b2_last_upload_at = timezone.now()
    app_settings.b2_last_upload_status = 'success'
    app_settings.b2_last_upload_filename = filename
    app_settings.b2_last_upload_error = ''
    return True, f'Uploaded {filename} to B2.'


def _authorize_and_resolve_bucket(app_settings) -> dict:
    """Authenticate with B2 and resolve the configured bucket name → bucketId.

    Returns a dict with: api_url, account_token, account_id, bucket_id,
    recommended_part_size, absolute_minimum_part_size. Raises B2Error on failure.
    """
    try:
        auth = requests.get(
            B2_AUTH_URL,
            auth=(app_settings.b2_application_key_id, app_settings.b2_application_key),
            timeout=30,
        )
    except requests.RequestException as e:
        raise B2Error(f'B2 auth network error: {e}')
    if auth.status_code != 200:
        raise B2Error(f'B2 auth failed: HTTP {auth.status_code} {auth.text[:200]}')

    auth_data = auth.json()
    storage_api = auth_data['apiInfo']['storageApi']
    api_url = storage_api['apiUrl']
    account_token = auth_data['authorizationToken']
    account_id = auth_data['accountId']
    recommended_part_size = storage_api.get('recommendedPartSize', 100 * 1024 * 1024)
    absolute_minimum_part_size = storage_api.get('absoluteMinimumPartSize', 5 * 1024 * 1024)
    allowed = storage_api.get('allowed') or {}

    bucket_id = allowed.get('bucketId')
    if bucket_id:
        if allowed.get('bucketName') and allowed['bucketName'] != app_settings.b2_bucket_name:
            raise B2Error(
                f'Application key is restricted to bucket "{allowed["bucketName"]}", '
                f'not "{app_settings.b2_bucket_name}".'
            )
    else:
        try:
            list_resp = requests.post(
                f'{api_url}/b2api/v3/b2_list_buckets',
                headers={'Authorization': account_token},
                json={'accountId': account_id, 'bucketName': app_settings.b2_bucket_name},
                timeout=30,
            )
        except requests.RequestException as e:
            raise B2Error(f'B2 list_buckets network error: {e}')
        if list_resp.status_code != 200:
            raise B2Error(f'B2 list_buckets failed: HTTP {list_resp.status_code} {list_resp.text[:200]}')
        buckets = list_resp.json().get('buckets', [])
        if not buckets:
            raise B2Error(f'Bucket "{app_settings.b2_bucket_name}" not found.')
        bucket_id = buckets[0]['bucketId']

    return {
        'api_url': api_url,
        'account_token': account_token,
        'account_id': account_id,
        'bucket_id': bucket_id,
        'recommended_part_size': recommended_part_size,
        'absolute_minimum_part_size': absolute_minimum_part_size,
    }


def _upload_single_shot(path: Path, size: int, ctx: dict) -> None:
    """Upload a small file in one POST. Raises B2Error on failure."""
    try:
        url_resp = requests.post(
            f'{ctx["api_url"]}/b2api/v3/b2_get_upload_url',
            headers={'Authorization': ctx['account_token']},
            json={'bucketId': ctx['bucket_id']},
            timeout=30,
        )
    except requests.RequestException as e:
        raise B2Error(f'B2 get_upload_url network error: {e}')
    if url_resp.status_code != 200:
        raise B2Error(f'B2 get_upload_url failed: HTTP {url_resp.status_code} {url_resp.text[:200]}')
    upload_data = url_resp.json()

    sha1 = _sha1_of_file(path)
    try:
        with open(path, 'rb') as f:
            put_resp = requests.post(
                upload_data['uploadUrl'],
                headers={
                    'Authorization': upload_data['authorizationToken'],
                    'X-Bz-File-Name': path.name,
                    'Content-Type': 'application/octet-stream',
                    'Content-Length': str(size),
                    'X-Bz-Content-Sha1': sha1,
                },
                data=f,
                timeout=600,
            )
    except requests.RequestException as e:
        raise B2Error(f'B2 upload network error: {e}')
    if put_resp.status_code != 200:
        raise B2Error(f'B2 upload failed: HTTP {put_resp.status_code} {put_resp.text[:200]}')


def _upload_large_file(path: Path, size: int, ctx: dict) -> None:
    """Upload a file using B2's large-file API. Raises B2Error on failure."""
    part_size = ctx['recommended_part_size']

    try:
        start_resp = requests.post(
            f'{ctx["api_url"]}/b2api/v3/b2_start_large_file',
            headers={'Authorization': ctx['account_token']},
            json={
                'bucketId': ctx['bucket_id'],
                'fileName': path.name,
                'contentType': 'application/octet-stream',
            },
            timeout=30,
        )
    except requests.RequestException as e:
        raise B2Error(f'B2 start_large_file network error: {e}')
    if start_resp.status_code != 200:
        raise B2Error(f'B2 start_large_file failed: HTTP {start_resp.status_code} {start_resp.text[:200]}')
    file_id = start_resp.json()['fileId']

    part_sha1s: list[str] = []
    try:
        with open(path, 'rb') as f:
            part_number = 1
            while True:
                chunk = f.read(part_size)
                if not chunk:
                    break
                part_sha1 = hashlib.sha1(chunk).hexdigest()

                try:
                    pu_resp = requests.post(
                        f'{ctx["api_url"]}/b2api/v3/b2_get_upload_part_url',
                        headers={'Authorization': ctx['account_token']},
                        json={'fileId': file_id},
                        timeout=30,
                    )
                except requests.RequestException as e:
                    raise B2Error(f'B2 get_upload_part_url network error (part {part_number}): {e}')
                if pu_resp.status_code != 200:
                    raise B2Error(
                        f'B2 get_upload_part_url failed (part {part_number}): '
                        f'HTTP {pu_resp.status_code} {pu_resp.text[:200]}'
                    )
                pu_data = pu_resp.json()

                try:
                    part_resp = requests.post(
                        pu_data['uploadUrl'],
                        headers={
                            'Authorization': pu_data['authorizationToken'],
                            'X-Bz-Part-Number': str(part_number),
                            'Content-Length': str(len(chunk)),
                            'X-Bz-Content-Sha1': part_sha1,
                        },
                        data=chunk,
                        timeout=600,
                    )
                except requests.RequestException as e:
                    raise B2Error(f'B2 upload_part network error (part {part_number}): {e}')
                if part_resp.status_code != 200:
                    raise B2Error(
                        f'B2 upload_part failed (part {part_number}): '
                        f'HTTP {part_resp.status_code} {part_resp.text[:200]}'
                    )
                part_sha1s.append(part_sha1)
                part_number += 1

        try:
            finish_resp = requests.post(
                f'{ctx["api_url"]}/b2api/v3/b2_finish_large_file',
                headers={'Authorization': ctx['account_token']},
                json={'fileId': file_id, 'partSha1Array': part_sha1s},
                timeout=60,
            )
        except requests.RequestException as e:
            raise B2Error(f'B2 finish_large_file network error: {e}')
        if finish_resp.status_code != 200:
            raise B2Error(
                f'B2 finish_large_file failed: HTTP {finish_resp.status_code} {finish_resp.text[:200]}'
            )
    except B2Error:
        try:
            requests.post(
                f'{ctx["api_url"]}/b2api/v3/b2_cancel_large_file',
                headers={'Authorization': ctx['account_token']},
                json={'fileId': file_id},
                timeout=30,
            )
        except requests.RequestException:
            pass
        raise


def upload_file(local_path, app_settings) -> tuple[bool, str]:
    path = Path(local_path)
    filename = path.name

    if not app_settings.b2_enabled:
        return _record_failure(app_settings, filename, 'B2 backup is not enabled.')
    if not (app_settings.b2_application_key_id and app_settings.b2_application_key and app_settings.b2_bucket_name):
        return _record_failure(app_settings, filename, 'B2 credentials or bucket name missing.')
    if not path.exists():
        return _record_failure(app_settings, filename, f'Local file not found: {local_path}')

    size = path.stat().st_size

    try:
        ctx = _authorize_and_resolve_bucket(app_settings)
        if size <= SINGLE_SHOT_LIMIT_BYTES:
            _upload_single_shot(path, size, ctx)
        else:
            _upload_large_file(path, size, ctx)
    except B2Error as e:
        return _record_failure(app_settings, filename, str(e))

    return _record_success(app_settings, filename)


def latest_backup_path(base_dir):
    backup_dir = Path(base_dir) / 'backups' / 'data'
    if not backup_dir.exists():
        return None
    archives = sorted(backup_dir.glob('backup_*.tar.gz'), reverse=True)
    return archives[0] if archives else None
