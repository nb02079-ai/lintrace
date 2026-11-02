"""테스트용 가짜 파일시스템을 만든다."""
import os
import shutil
import tempfile
import unittest


class FakeRootTest(unittest.TestCase):
    """make_root({'/etc/passwd': '...'})로 임시 루트를 만들고 테스트가 끝나면 지운다."""

    def make_root(self, files):
        root = tempfile.mkdtemp(prefix="lintrace-test-")
        self.addCleanup(shutil.rmtree, root, True)
        for path, content in files.items():
            full = os.path.join(root, path.lstrip("/"))
            if content is None:  # None이면 빈 디렉터리
                os.makedirs(full, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as f:
                f.write(content)
        return root
