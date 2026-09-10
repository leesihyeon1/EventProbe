"""SQL 덤프/DB 파일 노출 — 파일 내부 SQL 쿼리/덤프로 정밀 판별.

.sql 및 관련 확장자(.dump/.mysql/.pgsql/.psql/.sqldump)는 응답에 실제 SQL 문
(CREATE TABLE·INSERT INTO·mysqldump 헤더 등)이 있을 때만 노출로 확증한다.
SQLite DB(.sqlite/.sqlite3/.db)는 매직 헤더(SQLite format 3)로 확증. 비-SQL 내용은 미노출.
"""
import pytest

from core.analyzer import analyze_response, _fmt_sql


def _scan(body, path, ct="application/octet-stream"):
    r = analyze_response(200, {"content-type": ct}, body, 60,
                         payload=path, category="cve", url="http://t" + path)
    return r["attack_outcome"], [f["name"] for f in r["findings"] if f["verdict"] == "성공"]


# ── SQL 덤프 텍스트 ─────────────────────────────────────────────
@pytest.mark.parametrize("path,body", [
    ("/database.sql", "CREATE TABLE users (id INT);\nINSERT INTO users VALUES (1);"),
    ("/backup.dump", "-- MySQL dump 10.13\nLOCK TABLES `users` WRITE;"),
    ("/data.pgsql", "-- PostgreSQL database dump\nCREATE TABLE public.t (id integer);"),
    ("/x.mysql", "CREATE TABLE t (id INT) ENGINE=InnoDB;"),
    ("/db.psql", "INSERT INTO accounts VALUES (1, 'admin');"),
    ("/full.sqldump", "DROP TABLE IF EXISTS x;\nCREATE TABLE x (a INT);"),
])
def test_sql_dump_exposed_is_success(path, body):
    outcome, succ = _scan(body, path)
    assert outcome == "success"
    assert any("파일 노출" in n for n in succ)


# ── SQLite DB 파일(매직 바이트) ──────────────────────────────────
@pytest.mark.parametrize("path", ["/app.sqlite", "/data.sqlite3", "/store.db"])
def test_sqlite_db_magic_exposed(path):
    outcome, succ = _scan("SQLite format 3\x00\x10\x00\x01\x01\x00", path)
    assert outcome == "success"


# ── 오탐 방지 ────────────────────────────────────────────────────
@pytest.mark.parametrize("path,body,ct", [
    ("/database.sql", "<html>Not Found</html>", "text/html"),        # soft-404 HTML
    ("/data.db", "just random text, no sql here at all", "text/plain"),  # .db 비-SQLite
    ("/database.sql", '{"error":"access denied"}', "application/json"),  # JSON 에러
    ("/x.mysql", "you are not authorized to view this", "text/plain"),   # 평문 거부
])
def test_non_sql_content_not_exposed(path, body, ct):
    outcome, succ = _scan(body, path, ct)
    assert not succ
    assert outcome in ("safe", "blocked", "inconclusive")


# ── _fmt_sql 단위 ────────────────────────────────────────────────
def test_fmt_sql_units():
    assert _fmt_sql("CREATE TABLE x (id INT)")
    assert _fmt_sql("insert into t values (1)")           # 대소문자 무관
    assert _fmt_sql("-- MySQL dump\n")
    assert _fmt_sql("PRAGMA foreign_keys=ON;")
    assert _fmt_sql("SQLite format 3\x00")                # 매직
    assert _fmt_sql("GRANT ALL ON db.* TO 'u'@'%';")
    assert not _fmt_sql("<html>page</html>")
    assert not _fmt_sql("name,email\n1,a@b.com")          # CSV
    assert not _fmt_sql('{"k":"v"}')
    assert not _fmt_sql("")
