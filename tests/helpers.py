"""테스트용 가짜 파일시스템을 만든다."""
import os
import shutil
import tempfile
import unittest


def files_owned_by_root(test):
    """테스트 파일의 소유자가 root여야 '정상'으로 나오는 테스트.

    일반 계정으로 돌리면 테스트 파일 소유자가 실행 계정이 되어, 도구가 (올바르게)
    '다른 계정 소유의 파일'로 위험 판정한다. 소유자를 맞출 수 있는 root에서만 돌린다.
    """
    return unittest.skipIf(os.geteuid() != 0, "파일 소유자를 root로 맞출 수 있는 root에서만 확인 가능")(test)


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
            if isinstance(content, bytes):  # 바이너리 파일 (이미지 등)
                with open(full, "wb") as f:
                    f.write(content)
                continue
            with open(full, "w", encoding="utf-8") as f:
                f.write(content)
        return root
