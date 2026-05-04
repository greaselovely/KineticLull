"""
Backblaze B2 uploader using the native B2 API via `requests`.

Single-shot uploads only — files larger than 200 MB are rejected with a
clear error so the operator knows to extend this with the large-file API
or shrink the backup. The native API is used (not S3-compatible) to avoid
adding boto3 as a dependency.

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
    if size > SINGLE_SHOT_LIMIT_BYTES:
        mb = size // (1024 * 1024)
        return _record_failure(
            app_settings, filename,
            f'File is {mb} MB, exceeds {SINGLE_SHOT_LIMIT_BYTES // 1024 // 1024} MB single-shot limit.',
        )

    try:
        auth = requests.get(
            B2_AUTH_URL,
            auth=(app_settings.b2_application_key_id, app_settings.b2_application_key),
            timeout=30,
        )
        if auth.status_code != 200:
            return _record_failure(app_settings, filename, f'B2 auth failed: HTTP {auth.status_code} {auth.text[:200]}')
        auth_data = auth.json()
        api_url = auth_data['apiInfo']['storageApi']['apiUrl']
        account_token = auth_data['authorizationToken']
        allowed = auth_data['apiInfo']['storageApi'].get('allowed') or {}
        bucket_id = allowed.get('bucketId')
        if not bucket_id:
            list_resp = requests.post(
                f'{api_url}/b2api/v3/b2_list_buckets',
                headers={'Authorization': account_token},
                json={'accountId': auth_data['accountId'], 'bucketName': app_settings.b2_bucket_name},
                timeout=30,
            )
            if list_resp.status_code != 200:
                return _record_failure(
                    app_settings, filename,
                    f'B2 list_buckets failed: HTTP {list_resp.status_code} {list_resp.text[:200]}',
                )
            buckets = list_resp.json().get('buckets', [])
            if not buckets:
                return _record_failure(app_settings, filename, f'Bucket "{app_settings.b2_bucket_name}" not found.')
            bucket_id = buckets[0]['bucketId']
        elif allowed.get('bucketName') and allowed['bucketName'] != app_settings.b2_bucket_name:
            return _record_failure(
                app_settings, filename,
                f'Application key is restricted to bucket "{allowed["bucketName"]}", not "{app_settings.b2_bucket_name}".',
            )
    except requests.RequestException as e:
        return _record_failure(app_settings, filename, f'B2 auth network error: {e}')

    try:
        upload_url_resp = requests.post(
            f'{api_url}/b2api/v3/b2_get_upload_url',
            headers={'Authorization': account_token},
            json={'bucketId': bucket_id},
            timeout=30,
        )
        if upload_url_resp.status_code != 200:
            return _record_failure(
                app_settings, filename,
                f'B2 get_upload_url failed: HTTP {upload_url_resp.status_code} {upload_url_resp.text[:200]}',
            )
        upload_data = upload_url_resp.json()
        upload_url = upload_data['uploadUrl']
        upload_token = upload_data['authorizationToken']
    except requests.RequestException as e:
        return _record_failure(app_settings, filename, f'B2 get_upload_url network error: {e}')

    try:
        sha1 = _sha1_of_file(path)
        with open(path, 'rb') as f:
            put_resp = requests.post(
                upload_url,
                headers={
                    'Authorization': upload_token,
                    'X-Bz-File-Name': filename,
                    'Content-Type': 'application/octet-stream',
                    'Content-Length': str(size),
                    'X-Bz-Content-Sha1': sha1,
                },
                data=f,
                timeout=600,
            )
        if put_resp.status_code != 200:
            return _record_failure(
                app_settings, filename,
                f'B2 upload failed: HTTP {put_resp.status_code} {put_resp.text[:200]}',
            )
    except requests.RequestException as e:
        return _record_failure(app_settings, filename, f'B2 upload network error: {e}')

    return _record_success(app_settings, filename)


def latest_backup_path(base_dir):
    backup_dir = Path(base_dir) / 'backups' / 'data'
    if not backup_dir.exists():
        return None
    archives = sorted(backup_dir.glob('backup_*.tar.gz'), reverse=True)
    return archives[0] if archives else None
