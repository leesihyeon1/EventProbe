# ARTEX 개발 흐름

기준 브랜치는 `harden/artex-port-2026-11-08`입니다. 기능이나 수정 사항은 별도 작업 브랜치에서 개발하고 PR로 합칩니다.

## 한 번의 변경 작업

```bash
git fetch origin
git switch harden/artex-port-2026-11-08
git pull --ff-only origin harden/artex-port-2026-11-08
git switch -c codex/작업-이름

# 코드를 수정하고 로컬에서 확인
python -m pytest backend/tests -q
node --test frontend/tests/*.test.js

git add <변경한 파일>
git commit -m "fix: 변경 내용"
git push -u origin codex/작업-이름
```

GitHub에서 `codex/작업-이름` → `harden/artex-port-2026-11-08` PR을 엽니다. 변경 이유, 재현 방법, 테스트 결과를 PR 설명에 적고 Actions의 검사 결과를 확인합니다. 실패한 검사는 작업 브랜치에서 수정해 다시 푸시합니다. 검사가 통과하고 검토가 끝나면 PR을 병합합니다. 다음 작업을 시작할 때 ARTEX 브랜치를 다시 `pull --ff-only`로 갱신합니다.

## 자동 검사

`.github/workflows/artex-ci.yml`은 ARTEX 대상 PR, ARTEX에 대한 푸시, 수동 실행에서 동작합니다.

- **Backend tests and syntax**: Python 구문 검사, Ruff의 오류 중심 정적 검사 및 백엔드 전체 테스트
- **Frontend tests and syntax**: JavaScript 구문 검사 및 프런트엔드 전체 테스트
- **CodeQL (python / javascript-typescript)**: Python 및 JavaScript 보안 코드 검사

실제 병합 차단을 적용하려면 GitHub 저장소의 **Settings → Rules → Rulesets**에서 ARTEX 브랜치에 대한 규칙을 추가하고, PR 요구 및 위 검사들의 통과를 요구해야 합니다. 검사가 첫 실행을 마쳐야 선택 목록에 나타날 수 있습니다. 직접 푸시를 막고 싶다면 관리자 우회도 제한합니다.

테스트는 외부 서버를 스캔하지 않으며 API 키를 주입하지 않습니다. 민감한 로그나 `.env`는 커밋하지 않습니다.
