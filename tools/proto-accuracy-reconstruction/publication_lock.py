import atexit
import contextlib
import os
import stat
import time
from pathlib import Path


class PublicationLockError(RuntimeError):
    pass


def _verify_path_identity(path: Path, opened_metadata):
    try:
        path_metadata = os.lstat(path)
    except FileNotFoundError as error:
        raise PublicationLockError(f"lock pathname disappeared: {path}") from error
    if stat.S_ISLNK(path_metadata.st_mode):
        raise PublicationLockError(f"lock path is a symbolic link: {path}")
    if not stat.S_ISREG(path_metadata.st_mode) or path_metadata.st_nlink != 1:
        raise PublicationLockError(f"lock path is not a singly linked regular file: {path}")
    if ((path_metadata.st_dev, path_metadata.st_ino)
            != (opened_metadata.st_dev, opened_metadata.st_ino)):
        raise PublicationLockError(f"lock pathname no longer identifies the opened file: {path}")


def _open_lock_file(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing_metadata = os.lstat(path)
        if stat.S_ISLNK(existing_metadata.st_mode):
            raise PublicationLockError(f"lock path is a symbolic link: {path}")
    except FileNotFoundError:
        pass
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise PublicationLockError(f"could not safely open publication lock: {path}") from error
    opened_metadata = os.fstat(descriptor)
    try:
        _verify_path_identity(path, opened_metadata)
    except BaseException:
        os.close(descriptor)
        raise
    if opened_metadata.st_size == 0:
        os.write(descriptor, b"\0")
        os.fsync(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return os.fdopen(descriptor, "r+b", buffering=0)


@contextlib.contextmanager
def exclusive_lock(path, timeout=300.0, poll_interval=0.05):
    path = Path(path)
    stream = _open_lock_file(path)
    acquired = False
    deadline = time.monotonic() + timeout
    try:
        if os.name == "nt":
            import msvcrt

            while True:
                try:
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    acquired = True
                    break
                except OSError as error:
                    if time.monotonic() >= deadline:
                        raise PublicationLockError(f"timed out acquiring publication lock: {path}") from error
                    time.sleep(poll_interval)
        else:
            import fcntl

            while True:
                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except BlockingIOError as error:
                    if time.monotonic() >= deadline:
                        raise PublicationLockError(f"timed out acquiring publication lock: {path}") from error
                    time.sleep(poll_interval)
        _verify_path_identity(path, os.fstat(stream.fileno()))
        yield
    finally:
        if acquired:
            if os.name == "nt":
                import msvcrt

                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        stream.close()


def acquire_until_exit(path, timeout=300.0, poll_interval=0.05):
    lock = exclusive_lock(path, timeout=timeout, poll_interval=poll_interval)
    lock.__enter__()

    def release():
        lock.__exit__(None, None, None)

    atexit.register(release)
    return lock
