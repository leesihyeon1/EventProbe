"""Portable local run archive. Hashes detect corruption, not malicious forgery."""
import hashlib
import io
import json
import math
import re
import zipfile
import zlib

from core.agent_models import RunSpec


MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_CONTENT_BYTES = 50 * 1024 * 1024
FILES = {'manifest.json', 'run.json', 'events.json'}
STATES = {'paused', 'interrupted', 'limited', 'completed'}


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def build_archive(run, events):
    """Encode one inactive run and its original event IDs into a bounded ZIP."""
    if run['state'] not in STATES:
        raise ValueError('실행 중인 작업은 먼저 중단해야 보관 패키지로 내보낼 수 있습니다.')
    payloads = {'run.json': _json_bytes(run), 'events.json': _json_bytes(events)}
    if sum(len(value) for value in payloads.values()) > MAX_CONTENT_BYTES:
        raise ValueError('보관 패키지의 원본 증거 크기가 50 MiB 한도를 넘었습니다.')
    manifest = {'format': 'eventprobe-run-archive', 'version': 1,
                'run_id': run['id'], 'event_count': len(events),
                'sha256': {name: hashlib.sha256(value).hexdigest() for name, value in payloads.items()}}
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('manifest.json', _json_bytes(manifest))
        for name, value in payloads.items():
            archive.writestr(name, value)
    result = output.getvalue()
    if len(result) > MAX_ARCHIVE_BYTES:
        raise ValueError('보관 패키지가 25 MiB 한도를 넘었습니다.')
    return result


def read_archive(blob):
    """Validate names, sizes, version, checksums and identifiers before DB import."""
    if not isinstance(blob, bytes) or not blob or len(blob) > MAX_ARCHIVE_BYTES:
        raise ValueError('보관 패키지는 25 MiB 이하 ZIP 파일이어야 합니다.')
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            infos = archive.infolist()
            if len(infos) != 3 or {info.filename for info in infos} != FILES:
                raise ValueError('보관 패키지 파일 구성이 올바르지 않습니다.')
            if any(info.is_dir() or info.flag_bits & 0x1 for info in infos):
                raise ValueError('암호화되거나 디렉터리가 포함된 패키지는 지원하지 않습니다.')
            if sum(info.file_size for info in infos) > MAX_CONTENT_BYTES:
                raise ValueError('압축 해제 크기가 50 MiB 한도를 넘었습니다.')
            raw = {name: archive.read(name) for name in FILES}
    except (zipfile.BadZipFile, RuntimeError, OSError, zlib.error) as exc:
        raise ValueError('보관 패키지를 읽을 수 없습니다.') from exc
    try:
        manifest = json.loads(raw['manifest.json'])
        run = json.loads(raw['run.json'])
        events = json.loads(raw['events.json'])
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError('보관 패키지 JSON이 올바르지 않습니다.') from exc
    if not isinstance(manifest, dict) or manifest.get('format') != 'eventprobe-run-archive' or manifest.get('version') != 1:
        raise ValueError('지원하지 않는 보관 패키지 버전입니다.')
    if not isinstance(manifest.get('sha256'), dict):
        raise ValueError('보관 패키지 무결성 정보가 없습니다.')
    if any(manifest.get('sha256', {}).get(name) != hashlib.sha256(raw[name]).hexdigest()
           for name in ('run.json', 'events.json')):
        raise ValueError('보관 패키지 무결성 검사가 실패했습니다.')
    if not isinstance(run, dict) or not isinstance(events, list) or len(events) > 100000:
        raise ValueError('보관 패키지의 실행/이벤트 형식이 올바르지 않습니다.')
    run_id = run.get('id')
    if (not isinstance(run_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', run_id)
            or run_id != manifest.get('run_id') or len(events) != manifest.get('event_count')
            or run.get('state') not in STATES or not isinstance(run.get('data'), dict)
            or not isinstance(run['data'].get('spec'), dict)
            or not isinstance(run['data']['spec'].get('goal'), str)):
        raise ValueError('보관 패키지의 실행 정보가 올바르지 않습니다.')
    if any(not isinstance(run.get(key), (int, float)) or not math.isfinite(run[key])
           for key in ('created', 'updated')):
        raise ValueError('보관 패키지의 실행 시각이 올바르지 않습니다.')
    try:
        spec = RunSpec.model_validate(run['data']['spec'])
    except ValueError as exc:
        raise ValueError('보관 패키지의 실행 명세가 올바르지 않습니다.') from exc
    if spec.request.headers or any(actor.headers for actor in spec.actors):
        raise ValueError('보관 패키지 실행 명세에 자격증명 헤더가 포함돼 있습니다.')
    seen = set()
    for event in events:
        if (not isinstance(event, dict) or not isinstance(event.get('id'), str)
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', event['id'])
                or event['id'] in seen or event.get('run_id') != run_id
                or not isinstance(event.get('kind'), str)
                or not isinstance(event.get('step_id'), str)
                or not isinstance(event.get('data'), dict)
                or not isinstance(event.get('created'), (int, float))
                or not math.isfinite(event['created'])):
            raise ValueError('보관 패키지의 이벤트 연결이 올바르지 않습니다.')
        seen.add(event['id'])
    return run, events
