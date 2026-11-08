"""One live execution owner per SQLite file, released by the operating system."""
import os
from pathlib import Path


class RuntimeLock:
    def __init__(self, database_path):
        self.path = Path(str(Path(database_path).resolve()) + '.runtime.lock')
        self.handle = None

    def acquire(self):
        if self.handle is not None:
            return
        handle = self.path.open('a+b')
        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b'0')
                handle.flush()
            handle.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            raise RuntimeError('같은 실행 DB를 사용하는 서버가 이미 실행 중입니다. '
                               '단일 서버 프로세스로 실행하세요.') from exc
        except BaseException:
            handle.close()
            raise
        self.handle = handle

    def release(self):
        if self.handle is None:
            return
        handle, self.handle = self.handle, None
        try:
            handle.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
