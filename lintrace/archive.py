"""증거 아카이브 (--out DIR).

DIR/lintrace-<호스트>-<시각>/ 아래에
  report.txt, report.json   화면 리포트와 JSON 결과
  evidence/                 탐지 근거 파일의 복사본 (원래 경로 구조 그대로, 읽기 전용 0400)
  manifest.json             파일마다 원래 경로·크기·권한·소유자·mtime·ctime·inode·SHA-256
  SHA256SUMS                아카이브 안 모든 파일의 해시
를 만들고, 같은 내용을 DIR/lintrace-<호스트>-<시각>.tar.gz 하나로 묶는다.

- 복사 대상은 탐지 근거의 파일만이다 (점검 범위 전체를 복사하지 않는다).
- 프로세스가 붙잡은 지워진 파일(/proc/PID/fd/N, /proc/PID/exe)도 복사한다. 프로세스가
  재시작되면 사라지는 증거다. 실행 파일일 수 있으므로 실행 권한 없이 저장한다.
- 원본을 그대로 복사하므로 비밀 정보(비밀번호 해시 등)가 들어 있을 수 있다. 폴더는 0700.
- 복사하면 시각·권한이 바뀌므로 원래 값은 manifest.json에 남긴다.
- 점검 대상은 바꾸지 않는다. 쓰는 곳은 --out으로 지정한 폴더뿐이다.
"""
import datetime
import hashlib
import json
import os
import re
import stat
import tarfile

FILE_LIMIT = 50 * 1024 * 1024
TOTAL_LIMIT = 500 * 1024 * 1024
CHUNK = 1024 * 1024


def iso(ts):
    return datetime.datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text or "unknown").strip("_") or "unknown"


def evidence_sources(findings):
    """탐지 근거의 원본 경로 (절대 경로만, 나온 순서대로, 중복 없이)."""
    seen, out = set(), []
    for f in findings:
        for e in f.evidence:
            src = e.source
            if src.startswith("/") and src not in seen:
                seen.add(src)
                out.append(src)
    return out


class Archive:
    def __init__(self, out_dir, ctx, host, started_ts):
        stamp = datetime.datetime.fromtimestamp(started_ts).strftime("%Y%m%d-%H%M%S")
        self.name = "lintrace-{}-{}".format(safe_name(host), stamp)
        self.out_dir = out_dir
        self.dir = os.path.join(out_dir, self.name)
        self.ctx = ctx
        self.entries = []
        self.total = 0

    def create(self):
        os.makedirs(self.out_dir, exist_ok=True)
        base, n = self.name, 1
        while True:  # 같은 초에 두 번 실행해도 앞 결과를 덮어쓰지 않는다
            try:
                os.mkdir(self.dir, 0o700)
                break
            except FileExistsError:
                n += 1
                self.name = "{}-{}".format(base, n)
                self.dir = os.path.join(self.out_dir, self.name)
        os.chmod(self.dir, 0o700)
        os.mkdir(os.path.join(self.dir, "evidence"), 0o700)

    # --- 증거 복사 ---

    def add_evidence(self, source):
        full = self.ctx.path(source)
        entry = {"source": source, "copied": False, "path": None, "sha256": None, "note": None}
        self.entries.append(entry)
        try:
            lst = os.lstat(full)
            st = os.stat(full)  # 링크면 대상 (/proc/PID/fd/N은 지워진 원본)
        except OSError as e:
            entry["note"] = "읽을 수 없음: {}".format(e.strerror or e)
            return entry
        if stat.S_ISLNK(lst.st_mode):
            try:
                entry["link_target"] = os.readlink(full)
            except OSError:
                pass
        entry.update(original(st))
        if not stat.S_ISREG(st.st_mode):
            entry["note"] = "일반 파일이 아님 — 복사하지 않음"
            return entry
        if st.st_size > FILE_LIMIT or self.total + st.st_size > TOTAL_LIMIT:
            entry["sha256"] = sha256_of(full)
            entry["note"] = "크기 제한 초과 — 복사하지 않고 해시만 기록 (파일당 {}MB, 전체 {}MB)".format(
                FILE_LIMIT // (1024 * 1024), TOTAL_LIMIT // (1024 * 1024))
            return entry
        rel = "evidence" + source
        dest = os.path.join(self.dir, *rel.split("/"))
        os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
        h = hashlib.sha256()
        size = 0
        try:
            with open(full, "rb") as src:
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
                with os.fdopen(fd, "wb") as out:
                    for chunk in iter(lambda: src.read(CHUNK), b""):
                        size += len(chunk)
                        if size > FILE_LIMIT:
                            raise ValueError("복사 중 크기 제한 초과")
                        h.update(chunk)
                        out.write(chunk)
        except (OSError, ValueError) as e:
            if os.path.exists(dest):
                os.chmod(dest, 0o600)
                os.remove(dest)
            entry["note"] = "복사 실패: {}".format(getattr(e, "strerror", None) or e)
            return entry
        os.chmod(dest, 0o400)
        self.total += size
        entry.update({"copied": True, "path": rel, "sha256": h.hexdigest(), "copied_size": size})
        return entry

    # --- 마무리 ---

    def finish(self, report_text, report_json):
        write_text(os.path.join(self.dir, "report.txt"), report_text + "\n")
        write_text(os.path.join(self.dir, "report.json"),
                   json.dumps(report_json, ensure_ascii=False, indent=2) + "\n")
        manifest = {"schema": 1, "archive": self.name, "created": iso(self.ctx.now),
                    "file_limit": FILE_LIMIT, "total_limit": TOTAL_LIMIT,
                    "copied": sum(1 for e in self.entries if e["copied"]), "files": self.entries}
        write_text(os.path.join(self.dir, "manifest.json"), json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        sums = []
        for d, _, files in os.walk(self.dir):
            for name in files:
                full = os.path.join(d, name)
                rel = os.path.relpath(full, self.dir).replace(os.sep, "/")
                sums.append((rel, sha256_of(full)))
        write_text(os.path.join(self.dir, "SHA256SUMS"),
                   "".join("{}  {}\n".format(h, rel) for rel, h in sorted(sums)))
        tar_path = os.path.join(self.out_dir, self.name + ".tar.gz")
        fd = os.open(tar_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as raw:
            with tarfile.open(fileobj=raw, mode="w:gz") as tar:
                tar.add(self.dir, arcname=self.name)
        return tar_path, sha256_of(tar_path)


def original(st):
    return {"size": st.st_size, "mode": stat.filemode(st.st_mode), "uid": st.st_uid, "gid": st.st_gid,
            "inode": st.st_ino, "mtime": iso(st.st_mtime), "ctime": iso(st.st_ctime)}


def sha256_of(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def write_text(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def write(out_dir, ctx, host, started_ts, findings, report_text, report_json):
    """아카이브를 만들고 (폴더 경로, tar.gz 경로, tar.gz SHA-256, 복사한 파일 수, 근거 경로 수)를 돌려준다."""
    a = Archive(out_dir, ctx, host, started_ts)
    a.create()
    for src in evidence_sources(findings):
        a.add_evidence(src)
    report_json = dict(report_json)
    report_json["archive"] = {"name": a.name, "evidence_files": sum(1 for e in a.entries if e["copied"])}
    tar_path, digest = a.finish(report_text, report_json)
    return a.dir, tar_path, digest, sum(1 for e in a.entries if e["copied"]), len(a.entries)
