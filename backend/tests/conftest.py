"""pytest 공통 설정.

테스트가 `import core.analyzer` 처럼 앱과 동일한 방식으로 임포트하도록,
backend/ 디렉터리를 sys.path 에 추가한다(앱은 backend/ 를 루트로 실행됨).

이 테스트들은 전부 순수 함수 단위 테스트다 — 네트워크 요청을 전혀 보내지 않으며,
어떤 외부/고객사 대상에도 접속하지 않는다. 오프라인에서 실행해도 100% 동작한다.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


@pytest.fixture(autouse=True, scope="session")
def _neutralize_deploy_env():
    """배포용 .env(EVENTPROBE_TOKEN 등)가 엔드포인트 테스트를 401 로 막지 않게 한다.

    main.py 가 load_dotenv(override=True) 로 .env 를 강제 로드하므로, 로컬 배포 설정이
    있는 개발기에서 접근 토큰 가드가 TestClient 요청을 거부한다. 가드는 요청 시점에
    os.getenv 로 토큰을 읽으므로, main 임포트 이후 이 변수를 제거하면 테스트는 가드와
    무관하게(운영 코드/보안 로직은 그대로) 순수 단위 검증을 수행한다.
    """
    for _k in ("EVENTPROBE_TOKEN",):
        os.environ.pop(_k, None)
    yield
