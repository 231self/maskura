"""Generator-side FileIO that stores `s3://bucket/<key>` URIs on the local disk.

Only used while producing the golden fixtures (see `generate_fixtures.py`); it
makes pyiceberg write tables whose locations and file URIs are object-store
keys, so the fixtures load into the test object store byte for byte.
"""

from __future__ import annotations

import io
import pathlib

from pyiceberg.io import FileIO, InputFile, OutputStream, OutputFile

ROOT = pathlib.Path(__file__).resolve().parent / "_warehouse"


def _to_path(location: str) -> pathlib.Path:
    prefix = "s3://"
    if not location.startswith(prefix):
        raise ValueError(f"FakeS3FileIO only understands s3:// URIs: {location}")
    # Strip the bucket component: `s3://bucket/<key>` maps to `<key>`.
    _, _, key = location[len(prefix) :].partition("/")
    return ROOT / key


class FakeInputStream(io.RawIOBase):
    def __init__(self, path: pathlib.Path) -> None:
        super().__init__()
        self._fh = path.open("rb")

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        return self._fh.read(size)

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._fh.seek(offset, whence)

    def tell(self) -> int:
        return self._fh.tell()

    def close(self) -> None:
        self._fh.close()
        super().close()


class FakeOutputStream(io.RawIOBase):
    def __init__(self, path: pathlib.Path) -> None:
        super().__init__()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("wb")

    def writable(self) -> bool:
        return True

    def write(self, data: bytes) -> int:
        return self._fh.write(data)

    def close(self) -> None:
        self._fh.close()
        super().close()


class FakeS3InputFile(InputFile):
    def __len__(self) -> int:
        return _to_path(self.location).stat().st_size

    def exists(self) -> bool:
        return _to_path(self.location).exists()

    def open(self, seekable: bool = True) -> FakeInputStream:
        return FakeInputStream(_to_path(self.location))


class FakeS3OutputFile(OutputFile):
    def __len__(self) -> int:
        return _to_path(self.location).stat().st_size

    def exists(self) -> bool:
        return _to_path(self.location).exists()

    def to_input_file(self) -> FakeS3InputFile:
        return FakeS3InputFile(self.location)

    def create(self, overwrite: bool = False) -> OutputStream:
        path = _to_path(self.location)
        if path.exists() and not overwrite:
            raise FileExistsError(self.location)
        return FakeOutputStream(path)


class FakeS3FileIO(FileIO):
    def new_input(self, location: str) -> FakeS3InputFile:
        return FakeS3InputFile(location)

    def new_output(self, location: str) -> FakeS3OutputFile:
        return FakeS3OutputFile(location)

    def delete(self, location) -> None:
        target = location if isinstance(location, str) else location.location
        _to_path(target).unlink(missing_ok=True)
