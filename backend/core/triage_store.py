"""Owner-scoped opt-in log retention and local service inventory."""
import csv
import hashlib
import io
import json
import sqlite3
import time
import uuid
from datetime import datetime
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit
from core.agent_models import origin


class TriageStore:
    def __init__(self,path):
        self.path=Path(path)
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with self.connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS triage_batches (
              id TEXT PRIMARY KEY, owner TEXT NOT NULL, digest TEXT NOT NULL,
              created REAL NOT NULL, expires REAL NOT NULL, raw TEXT NOT NULL,
              result TEXT NOT NULL, UNIQUE(owner,digest));
            CREATE TABLE IF NOT EXISTS triage_event_refs (
              batch_id TEXT NOT NULL, owner TEXT NOT NULL, fingerprint TEXT NOT NULL,
              FOREIGN KEY(batch_id) REFERENCES triage_batches(id) ON DELETE CASCADE);
            CREATE INDEX IF NOT EXISTS triage_refs ON triage_event_refs(owner,fingerprint);
            CREATE TABLE IF NOT EXISTS triage_inventory (
              owner TEXT NOT NULL, origin TEXT NOT NULL, data TEXT NOT NULL,
              PRIMARY KEY(owner,origin));
            """)

    @contextmanager
    def connect(self):
        db=sqlite3.connect(self.path,timeout=10)
        db.row_factory=sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def purge(db):
        db.execute('DELETE FROM triage_batches WHERE expires<=?',(time.time(),))

    def save(self,owner,text,result,days):
        if not 1<=days<=30: raise ValueError('보존 기간은 1~30일입니다.')
        digest=hashlib.sha256(text.encode()).hexdigest()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            self.purge(db)
            prior=db.execute('SELECT id,created,expires FROM triage_batches WHERE owner=? AND digest=?',(owner,digest)).fetchone()
            if prior:return dict(prior,duplicate=True,overlap_events=0)
            # Compare full parsed fields, retaining payload values and every source record.
            fingerprints=[hashlib.sha256(json.dumps(e['fields'],sort_keys=True,ensure_ascii=False).encode()).hexdigest() for e in result['events']]
            overlap=sum(bool(db.execute('SELECT 1 FROM triage_event_refs WHERE owner=? AND fingerprint=? LIMIT 1',(owner,f)).fetchone()) for f in fingerprints)
            count=db.execute('SELECT COUNT(*) FROM triage_batches WHERE owner=?',(owner,)).fetchone()[0]
            if count>=100:raise ValueError('저장 한도 100개입니다. 기존 기록을 삭제하세요.')
            now=time.time();bid=uuid.uuid4().hex;expires=now+days*86400
            result=dict(result,persisted=True)
            db.execute('INSERT INTO triage_batches VALUES (?,?,?,?,?,?,?)',(bid,owner,digest,now,expires,text,json.dumps(result,ensure_ascii=False)))
            db.executemany('INSERT INTO triage_event_refs VALUES (?,?,?)',[(bid,owner,f) for f in fingerprints])
            return dict(id=bid,created=now,expires=expires,duplicate=False,overlap_events=overlap)

    def cleanup(self):
        with self.connect() as db:
            self.purge(db)

    def batches(self,owner):
        with self.connect() as db:
            self.purge(db)
            rows=db.execute("SELECT id,created,expires,json_extract(result,'$.summary') AS summary FROM triage_batches WHERE owner=? ORDER BY created DESC",(owner,)).fetchall()
            return [dict(id=r['id'],created=r['created'],expires=r['expires'],summary=json.loads(r['summary'])) for r in rows]

    def batch(self,owner,bid):
        with self.connect() as db:
            self.purge(db)
            r=db.execute('SELECT result FROM triage_batches WHERE owner=? AND id=?',(owner,bid)).fetchone()
            if not r:raise KeyError(bid)
            return json.loads(r['result'])

    def delete(self,owner,bid):
        with self.connect() as db:
            return db.execute('DELETE FROM triage_batches WHERE owner=? AND id=?',(owner,bid)).rowcount>0

    def inventory(self,owner):
        with self.connect() as db:
            return [json.loads(r[0]) for r in db.execute('SELECT data FROM triage_inventory WHERE owner=? ORDER BY origin',(owner,))]

    def import_inventory(self,owner,text):
        rows=list(csv.DictReader(io.StringIO(text)))
        if not rows or len(rows)>500:raise ValueError('CSV는 1~500개 자산을 포함해야 합니다.')
        clean=[];seen=set()
        for n,row in enumerate(rows,2):
            value=(row.get('origin') or '').strip()
            try:
                origin(value);u=urlsplit(value)
                if u.path not in ('','/') or u.query or u.fragment:raise ValueError()
                normalized=f'{u.scheme}://{u.netloc.lower()}'
                if normalized in seen:raise ValueError()
                seen.add(normalized)
                importance=row.get('importance','').strip()
                if importance not in ('high','medium','low'):raise ValueError()
                checked=datetime.fromisoformat(row.get('verified_at','').replace('Z','+00:00'))
                if not checked.tzinfo or checked.timestamp()>time.time()+60:raise ValueError()
                item=dict(origin=normalized,importance=importance,verified_at=checked.timestamp())
                for key in ('service','contact','stack','environment'):
                    item[key]=(row.get(key) or '').strip()
                    if len(item[key])>200:raise ValueError()
                clean.append(item)
            except (ValueError,TypeError,OverflowError):
                raise ValueError(f'{n}행: origin, importance(high/medium/low), 시간대 포함 verified_at과 필드 길이를 확인하세요.')
        with self.connect() as db:
            for item in clean:
                db.execute('INSERT OR REPLACE INTO triage_inventory VALUES (?,?,?)',(owner,item['origin'],json.dumps(item,ensure_ascii=False)))
        return len(clean)

    def delete_inventory(self,owner,value):
        with self.connect() as db:
            return db.execute('DELETE FROM triage_inventory WHERE owner=? AND origin=?',(owner,value)).rowcount>0

    def enrich(self,owner,result):
        inventory=self.inventory(owner)
        for e in result['events']:
            matches=[i for i in inventory if urlsplit(i['origin']).netloc.lower()==e['host'].lower()]
            if len(matches)!=1 or any(r in e['reasons'] for r in ('HOST_CONFLICT','HOST_MISSING')):
                e['inventory']=None
                continue
            item=dict(matches[0]);item['stale']=time.time()-item['verified_at']>30*86400
            e['inventory']=item
            if item['stale']:e['reasons'].append('INVENTORY_STALE')
            elif item['importance']=='high':
                e['reasons'].append('IMPORTANT_ASSET')
                if e['priority']=='information':e['priority']='review'
        for bucket in ('review','information','low'):
            result['summary'][bucket]=sum(e['priority']==bucket for e in result['events'])
        return result
