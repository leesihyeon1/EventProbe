"""기능별 AI 시스템 프롬프트 로더 — backend/prompts/*.md 에서 읽어 캐시한다.

프롬프트를 코드에서 분리해 (1) 배포 없이 튜닝·리뷰하고 (2) 로컬 모델로 갈아끼울 때
모델 성향에 맞춰 파일만 고치면 되게 한다. 파일 mtime 을 보고 바뀌면 자동 재로딩하므로
서버 재시작 없이 프롬프트를 조정할 수 있다.

파일 맨 위의 <!-- ... --> 주석 블록은 사람용 메모로 취급해 모델 전송에서 제거한다.
"""
import os
import re

_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "prompts")
_cache: dict = {}   # name -> (mtime, text)

_LEAD_COMMENT = re.compile(r"^\s*<!--.*?-->\s*", re.DOTALL)


def _path(name: str) -> str:
    return os.path.join(_DIR, f"{name}.md")


def load(name: str) -> str:
    """프롬프트 파일 본문을 반환(맨 위 <!-- 메모 --> 제거, 앞뒤 공백 정리).
    파일이 없으면 FileNotFoundError — 조용한 빈 프롬프트로 흐르지 않게 조기 실패."""
    path = _path(name)
    mtime = os.path.getmtime(path)
    cached = _cache.get(name)
    if cached and cached[0] == mtime:
        return cached[1]
    with open(path, encoding="utf-8") as f:
        text = _LEAD_COMMENT.sub("", f.read()).strip()
    _cache[name] = (mtime, text)
    return text
