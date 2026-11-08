"""Validated metadata only. Keys are resolved from approved environment names at call time."""
import os
import re
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ModelProfile(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    name: str = Field(min_length=1, max_length=100)
    model: str = Field(min_length=1, max_length=200)
    base_url: str = Field(min_length=1, max_length=500)
    key_env: str = Field(default='AI_API_KEY', max_length=100)
    enabled: bool = True
    timeout_seconds: int = Field(default=120, ge=10, le=300)
    min_interval_seconds: float = Field(default=0.0, ge=0, le=60, allow_inf_nan=False)
    max_concurrent_calls: int = Field(default=1, ge=1, le=16)
    failure_threshold: int = Field(default=2, ge=1, le=10)
    cooldown_seconds: int = Field(default=30, ge=1, le=3600)

    @model_validator(mode='after')
    def validate_metadata(self):
        if any(ord(c) < 32 for c in self.name + self.model + self.base_url):
            raise ValueError('프로파일에 제어문자를 사용할 수 없습니다.')
        self.name, self.model = self.name.strip(), self.model.strip()
        self.base_url = self.base_url.strip().rstrip('/')
        parsed = urlsplit(self.base_url)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname or
                parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise ValueError('인증정보·쿼리 없는 HTTP(S) 모델 기본 주소가 필요합니다.')
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError('모델 주소 포트가 잘못됐습니다.') from exc
        if not self.name or not self.model or parsed.path.endswith('/chat/completions'):
            raise ValueError('모델명과 /chat/completions 이전의 기본 주소를 지정하세요.')
        if not re.fullmatch(r'(?:AI_API_KEY|NVIDIA_API_KEY|EVENTPROBE_MODEL_[A-Z0-9_]{1,70})', self.key_env):
            raise ValueError('AI_API_KEY, NVIDIA_API_KEY 또는 EVENTPROBE_MODEL_* 환경변수만 참조할 수 있습니다.')
        return self


def legacy_profile():
    """Preserve the established environment-variable precedence without storing a key."""
    return {'id': 'default', 'revision': 0, 'name': '기존 환경 설정',
            'model': (os.getenv('AI_MODEL') or os.getenv('NVIDIA_MODEL') or
                      'meta/llama-3.2-11b-vision-instruct').strip(),
            'base_url': (os.getenv('AI_BASE_URL') or os.getenv('NVIDIA_BASE_URL') or
                         'https://integrate.api.nvidia.com/v1').strip().rstrip('/'),
            'key_env': 'AI_API_KEY' if os.getenv('AI_API_KEY', '').strip() else 'NVIDIA_API_KEY',
            'enabled': True, 'timeout_seconds': legacy_timeout(),
            'min_interval_seconds': 0.0, 'max_concurrent_calls': 1,
            'failure_threshold': 2, 'cooldown_seconds': 30}


def legacy_timeout():
    try:
        return max(10, min(300, int(float(os.getenv('AI_TIMEOUT', '120')))))
    except (ValueError, OverflowError):
        return 120


def resolve_key(profile):
    return os.getenv(profile['key_env'], '').strip()
