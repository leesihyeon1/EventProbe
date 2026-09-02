"""pytest 공통 설정.

테스트가 `import core.analyzer` 처럼 앱과 동일한 방식으로 임포트하도록,
backend/ 디렉터리를 sys.path 에 추가한다(앱은 backend/ 를 루트로 실행됨).

이 테스트들은 전부 순수 함수 단위 테스트다 — 네트워크 요청을 전혀 보내지 않으며,
어떤 외부/고객사 대상에도 접속하지 않는다. 오프라인에서 실행해도 100% 동작한다.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
