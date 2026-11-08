"""Task-scoped, non-streaming chat routing. Only model calls may fail over.

No HTTP verification, action execution or transcript is replayed here. Every
destination still crosses the existing egress guard immediately before I/O.
"""
import asyncio
from contextlib import contextmanager, asynccontextmanager
from contextvars import ContextVar
import copy
import time
import weakref

import httpx

from core import ai_egress
from core.model_profiles import resolve_key
from core.model_store import ModelCallBudgetExceeded

ACTIVE_MODEL = ContextVar('eventprobe_model_route', default=None)
PREPAID_MODEL_ATTEMPT = ContextVar('eventprobe_prepaid_model_attempt', default=False)
FAILOVER_CODES = {'quota', 'auth', 'rate_limited', 'temporary', 'transport'}


class ModelUnavailable(ValueError):
    pass


def validate_chain(store, profile_ids):
    if (not isinstance(profile_ids, list) or len(profile_ids) > 8 or
            any(not isinstance(x, str) or not x or len(x) > 100 for x in profile_ids) or
            len(set(profile_ids)) != len(profile_ids)):
        raise ValueError('중복 없는 모델 프로파일 ID를 최대 8개 지정하세요.')
    profiles = [store.model_profile(key) for key in profile_ids or ['default']]
    if any(not p['enabled'] for p in profiles):
        raise ValueError('비활성 모델 프로파일은 실행 순서에 넣을 수 없습니다.')
    zones = {ai_egress.is_internal_destination(p['base_url']) for p in profiles}
    if len(zones) > 1:
        raise ValueError('내부 모델과 외부 모델을 같은 장애 전환 순서에 혼합할 수 없습니다.')
    return profiles


@contextmanager
def prepaid_model_attempt():
    """The existing planner has already counted this one logical invocation."""
    token = PREPAID_MODEL_ATTEMPT.set(True)
    try:
        yield
    finally:
        PREPAID_MODEL_ATTEMPT.reset(token)


class ProfileLimiter:
    def __init__(self):
        self.condition = asyncio.Condition()
        self.active = 0
        self.last_start = None

    @asynccontextmanager
    async def slot(self, profile):
        async with self.condition:
            while self.active >= profile['max_concurrent_calls']:
                await self.condition.wait()
            if self.last_start is not None:
                delay = profile['min_interval_seconds'] - (time.monotonic() - self.last_start)
                if delay > 0:
                    await asyncio.sleep(delay)
            self.active += 1
            self.last_start = time.monotonic()
        try:
            yield
        finally:
            async with self.condition:
                self.active -= 1
                self.condition.notify_all()


class ModelRouter:
    def __init__(self, store):
        self.store = store
        self._limiters = weakref.WeakKeyDictionary()

    def limiter(self, profile_id):
        by_profile = self._limiters.setdefault(asyncio.get_running_loop(), {})
        return by_profile.setdefault(profile_id, ProfileLimiter())

    @contextmanager
    def bind(self, run_id=None, profile_ids=None, preview_budget=1):
        route = BoundModel(self, run_id, profile_ids, preview_budget)
        token = ACTIVE_MODEL.set(route)
        try:
            yield route
        finally:
            ACTIVE_MODEL.reset(token)


class BoundModel:
    def __init__(self, router, run_id, profile_ids, preview_budget):
        self.router, self.store, self.run_id = router, router.store, run_id
        self.preview_ids = profile_ids or []
        self.preview_position = 0
        self.preview_remaining = preview_budget

    def chain(self):
        chain = (self.store.run_model_chain(self.run_id) if self.run_id is not None else
                 {'profile_ids': self.preview_ids, 'revision': 0, 'active_position': self.preview_position})
        profiles = validate_chain(self.store, chain['profile_ids'])
        return chain, profiles

    def eligible(self):
        chain, profiles = self.chain()
        start = min(chain['active_position'], len(profiles) - 1)
        ordered = [(i, profiles[i]) for i in [*range(start, len(profiles)), *range(start)]]
        return chain, [(i, p) for i, p in ordered if resolve_key(p) and
                       self.store.model_health(p['id'])['cooldown_until'] <= time.time()]

    def current(self):
        _, ready = self.eligible()
        if ready:
            return ready[0][1]
        return self.chain()[1][0]

    def enabled(self):
        return bool(self.eligible()[1])

    async def post_chat(self, payload):
        from core import ai_analyzer as ai
        chain, candidates = self.eligible()
        if not candidates:
            raise ModelUnavailable('사용 가능한 모델이 없습니다. 키 설정과 모델 냉각 상태를 확인하세요.')
        last_response = None
        for position, profile in candidates:
            # Profile edits or a chain edit affect the next logical call, not the
            # already captured chain for this in-flight call.
            call_payload = copy.deepcopy(payload)
            call_payload['model'] = profile['model']
            async with self.router.limiter(profile['id']).slot(profile):
                if self.run_id is None:
                    if self.preview_remaining <= 0:
                        raise ModelCallBudgetExceeded('계획 미리보기의 AI 호출 한도에 도달했습니다.')
                    self.preview_remaining -= 1
                prepaid = self.run_id is not None and PREPAID_MODEL_ATTEMPT.get()
                if prepaid:
                    PREPAID_MODEL_ATTEMPT.set(False)
                call_id = self.store.begin_model_call(self.run_id, profile, prepaid=prepaid)
                tick, error, response, status, tokens = time.monotonic(), 'internal_error', None, 'error', None
                try:
                    # The direct transport always rechecks ai_egress.guard and
                    # refuses redirects; no provider header/key is persisted.
                    response = await ai._post_chat_direct(
                        profile['base_url'], {'Authorization': 'Bearer ' + resolve_key(profile),
                                              'Content-Type': 'application/json'},
                        call_payload, tries=1, timeout_seconds=profile['timeout_seconds'])
                    error = classify_failure(response)
                    status = 'completed' if response.status_code == 200 else 'error'
                    tokens = actual_usage(response)
                except asyncio.CancelledError:
                    status, error = 'cancelled', 'cancelled'
                    raise
                except ai_egress.EgressBlocked:
                    status, error = 'blocked', 'egress_blocked'
                    raise
                except httpx.TransportError:
                    error = 'transport'
                finally:
                    self.store.finish_model_call(call_id, status,
                        response.status_code if response is not None else None,
                        error, (time.monotonic() - tick) * 1000, tokens)
            if response is not None and error not in FAILOVER_CODES:
                if response.status_code == 200:
                    self.store.record_model_health(profile, '')
                self._cursor(chain['revision'], position)
                return response
            self.store.record_model_health(profile, error)
            self._cursor(chain['revision'], (position + 1) % len(chain['profile_ids'] or ['default']))
            if response is not None:
                last_response = response
        if last_response is not None:
            return last_response
        raise ModelUnavailable('모델 연결에 실패했습니다. 대상 검증 요청은 재실행하지 않았습니다.')

    def _cursor(self, revision, position):
        if self.run_id is not None:
            self.store.advance_model_cursor(self.run_id, revision, position)
        else:
            self.preview_position = position


def classify_failure(response):
    status = response.status_code
    if status == 402:
        return 'quota'
    if status == 401:
        return 'auth'
    if status == 403 and any(x in response.text[:2000].lower() for x in
                             ('quota', 'credit', 'billing', 'insufficient balance')):
        return 'quota'
    if status == 429:
        return 'rate_limited'
    if status in (404, 408, 409) or 500 <= status <= 599:
        return 'temporary'
    # Invalid requests, permissions, redirects and invalid successful output
    # are not reasons to replay the same payload on another backend.
    if status == 200:
        return ''
    if 300 <= status < 400:
        return 'redirect'
    if status == 403:
        return 'permission'
    if 400 <= status < 500:
        return 'invalid_request'
    return 'unexpected_status'


def actual_usage(response):
    try:
        value = (response.json().get('usage') or {}).get('total_tokens')
        return value if type(value) is int and value >= 0 else None
    except (ValueError, TypeError, AttributeError):
        return None
