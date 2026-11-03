"""FS-06 웹 루트의 웹쉘 패턴.

웹 서버가 실행하는 폴더(웹 루트)에서 웹쉘의 전형적인 코드 모양을 찾는다.

웹 루트 찾기: /var/www, nginx 설정의 root·alias, Apache 설정의 DocumentRoot·Alias.
대상 파일: 서버 쪽 스크립트(.php .phtml .php3~8 .phar .inc .jsp .jspx .asp .aspx .cgi .pl .py)와
          이미지 파일(PHP 코드를 숨겼는지 확인). 2MB가 넘는 파일은 건너뛴다.

판정
- 심각: 요청 값이 실행 함수로 바로 들어감 (eval($_POST[..]), system($_GET[..]), $_GET['f']($_GET['c']))
- 심각: 인코딩을 풀어 바로 실행 (eval(base64_decode(..)), eval(gzinflate(..)))
- 심각: 이미지 확장자 파일 안에 PHP 코드 (업로드 검사 우회)
- 위험: 업로드 폴더(uploads, upload, user_files, attachments) 안의 스크립트 — 주석뿐인 빈 index.php는 제외
- 위험: 실행 함수 없이 긴 인코딩 문자열을 푸는 코드만 있음 (난독화)

PHP 파일은 실제로 실행되는 코드 부분만 본다. PHP 태그 밖(HTML)과 주석은 공백으로 지우고
(줄 번호 유지), 백틱은 문자열 밖에 있는 진짜 셸 실행 구간만 본다. WordPress 코어의 문서 주석
(`$_POST` 같은 마크다운 표기)과 SQL 문자열 속 백틱이 웹쉘로 잡히던 오탐을 막기 위해서다.

알려진 한계: 패턴 기반이라 새로 난독화된 웹쉘은 놓칠 수 있다. 실제 웹 애플리케이션의
오탐 수준은 WordPress를 설치한 Ubuntu VM에서 측정한다 (validation/README.md).
"""
import os
import posixpath
import re
import stat

from .. import timefmt
from .base import Check, Context, Evidence, Unavailable

SCRIPT_EXT = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8", ".phar", ".inc",
              ".jsp", ".jspx", ".asp", ".aspx", ".cgi", ".pl", ".py"}
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".webp", ".tif", ".tiff"}
PHP_EXT = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8", ".phar", ".inc"}
# images·media·files는 라이브러리 코드 폴더 이름으로도 흔해(src/Files, block-library/image) 넣지 않는다.
# 소문자 그대로만 비교한다.
UPLOAD_DIRS = {"uploads", "upload", "user_files", "attachments"}
MAX_BYTES = 2 * 1024 * 1024
NGINX_CONF = ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d", "/etc/nginx/sites-enabled"]
APACHE_CONF = ["/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled", "/etc/apache2/conf-enabled"]

REQUEST = r"(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|php://input|getallheaders\s*\()"
# ->exec(), ::exec(), $obj->system() 같은 메서드 호출은 셸 실행이 아니므로 뺀다
EXEC = r"(?<![\w>:$])(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|create_function)"
DECODE = r"(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|convert_uudecode)"

REQ_TO_EXEC = [
    re.compile(EXEC + r"\s*\(\s*[^;]{0,200}?" + REQUEST, re.I),
    re.compile(r"`[^`;]{0,200}" + REQUEST),            # `$_GET[c]` — PHP 파일은 대신 백틱 구간으로 본다
    re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(", re.I),      # $_GET['f'](...)
    re.compile(r"preg_replace\s*\(\s*['\"]([^\w\s])[^'\"]*\1[a-zA-Z]*e[a-zA-Z]*['\"]"),  # /e 수정자
]
DECODE_EXEC = re.compile(r"(?<![\w>:$])(?:eval|assert)\s*\(\s*@?\s*" + DECODE + r"\s*\(", re.I)
LONG_DECODE = re.compile(DECODE + r"\s*\(\s*['\"][A-Za-z0-9+/=\\]{200,}['\"]", re.I)
# 이미지 바이너리에 우연히 '<?='가 나오는 경우가 있어(테마 screenshot.png) 뒤 글자까지 본다
IMAGE_PHP = re.compile(rb"<\?php[\s(]|<\?=\s*[$@(]", re.I)
PHP_OPEN_TAG = re.compile(r"<\?(?:php\b|=|(?=\s))", re.I)
PHP_TOKEN = re.compile(r"\?>|['\"`#]|/[/*]|<<<")
STRING = {"'": re.compile(r"'(?:[^'\\]|\\.)*'?", re.S), '"': re.compile(r'"(?:[^"\\]|\\.)*"?', re.S)}
REQUEST_RE = re.compile(REQUEST)
# 아래 규칙은 모두 요청 값·디코딩 함수·preg_replace 중 하나가 있어야 걸리므로, 없는 파일은 해석을 건너뛴다
# (소문자로 바꾼 글에서 문자열 포함 여부만 보는 빠른 걸러내기 — 정규식 검사보다 수십 배 빠르다)
QUICK_WORDS = ("$_get", "$_post", "$_request", "$_cookie", "$_server", "$_files", "php://input", "getallheaders",
               "base64_decode", "gzinflate", "gzuncompress", "gzdecode", "str_rot13", "strrev", "hex2bin",
               "convert_uudecode", "preg_replace")
NOT_NEWLINE = re.compile(r"[^\n]")
LINE_COMMENT_END = re.compile(r"\n|\?>|\Z")
HEREDOC = re.compile(r"<<<[ \t]*(['\"]?)([A-Za-z_]\w*)\1")
PHP_COMMENTS = re.compile(r"/\*.*?\*/|//[^\n]*|#[^\n]*", re.S)


def ext_of(path):
    return posixpath.splitext(path)[1].lower()


def is_empty_php(text):
    """주석과 여는·닫는 태그만 있는 파일 ('Silence is golden' index.php 등)."""
    body = PHP_COMMENTS.sub("", text)
    body = re.sub(r"<\?php|<\?=|<\?|\?>", "", body, flags=re.I)
    return not body.strip()


def php_code(text):
    """PHP 코드 부분만 남긴 글과 백틱(셸 실행) 구간 목록.

    태그 밖 HTML과 주석은 공백으로 바꾸고 줄바꿈은 남겨, 위치와 줄 번호가 원문과 같다.
    문자열·heredoc은 그대로 두되 그 안의 백틱·주석 기호는 건너뛴다. '#['는 PHP 8 속성이라 주석이 아니다.
    """
    out = list(text)
    n = len(text)
    ticks = []

    def blank(a, b):
        out[a:b] = NOT_NEWLINE.sub(" ", text[a:b])

    i = 0
    while i < n:
        m = PHP_OPEN_TAG.search(text, i)
        if not m:
            blank(i, n)
            break
        blank(i, m.start())
        i = m.end()
        while i < n:
            t = PHP_TOKEN.search(text, i)
            if not t:
                i = n
                break
            i, tok = t.start(), t.group()
            if tok == "?>":
                i += 2
                break
            if tok in ("'", '"'):
                i = STRING[tok].match(text, i).end()
            elif tok == "`":
                k = text.find("`", i + 1)
                k = n - 1 if k < 0 else k
                ticks.append((i, k + 1))
                i = k + 1
            elif tok == "/*":
                k = text.find("*/", i + 2)
                k = n if k < 0 else k + 2
                blank(i, k)
                i = k
            elif tok == "#" and text.startswith("#[", i):
                i += 2
            elif tok in ("//", "#"):
                k = LINE_COMMENT_END.search(text, i).start()  # 줄 끝이나 '?>'에서 끝난다
                blank(i, k)
                i = k
            else:  # <<<
                h = HEREDOC.match(text, i)
                if not h:
                    i += 3
                    continue
                e = re.compile(r"^[ \t]*" + h.group(2) + r"\b", re.M).search(text, h.end())
                i = e.end() if e else n
    return "".join(out), ticks


def snippet(text, start, end):
    """걸린 부분 앞뒤를 짧게 잘라 한 줄로 보여준다 (긴 인코딩 문자열이 근거를 덮지 않게)."""
    s = text[max(0, start - 30):min(len(text), end + 40)]
    s = re.sub(r"\s+", " ", s).strip()
    s = re.sub(r"([A-Za-z0-9+/=]{40})[A-Za-z0-9+/=]{20,}", r"\1…", s)
    return s if len(s) <= 140 else s[:140] + "…"


def config_paths(ctx, entries):
    """설정 파일 목록 (폴더면 그 안의 파일들)."""
    out = []
    for p in entries:
        st = ctx.stat(p, follow=True)
        if st is None:
            continue
        if stat.S_ISDIR(st.st_mode):
            out += [posixpath.join(p, n) for n in ctx.list_dir(p)]
        else:
            out.append(p)
    return out


class Fs06(Check):
    id = "FS-06"
    title = "웹 루트의 웹쉘 패턴"
    severity = "critical"
    attack = "T1505.003"

    def run(self, ctx: Context):
        roots = self.web_roots(ctx)
        self.files_checked, denied, findings = 0, [], []
        for root in roots:
            for path, st in self.walk(ctx, root, denied):
                f = self.check_file(ctx, path, st)
                if f:
                    findings.append(f)
        findings.sort(key=lambda f: f.evidence[0].source)  # 폴더를 읽는 순서와 관계없이 같은 결과
        if denied and os.geteuid() != 0:
            raise Unavailable("웹 루트 안 디렉터리 {}개를 읽을 권한 없음 (root로 실행 필요)".format(len(denied)))
        self.scope = "웹 루트 {}개{}, 스크립트·이미지 파일 {:,}개".format(
            len(roots), " ({})".format(", ".join(roots)) if roots else "", self.files_checked)
        if denied:
            self.scope += ", root로도 읽지 못한 디렉터리 {}개".format(len(denied))
        return findings

    # --- 웹 루트 찾기 ---

    def web_roots(self, ctx):
        found = []
        if ctx.stat("/var/www", follow=True) is not None:
            found.append("/var/www")
        for path in config_paths(ctx, NGINX_CONF):
            for line in ctx.read_lines(path, missing_ok=True):
                s = line.split("#", 1)[0]
                # 한 줄짜리 블록(location /s { alias /opt/static/; })도 있어 줄 중간까지 본다
                for m in re.finditer(r"(?:^|[{;])\s*(?:root|alias)\s+['\"]?([^'\";\s]+)", s):
                    found.append(m.group(1))
        for path in config_paths(ctx, APACHE_CONF):
            for line in ctx.read_lines(path, missing_ok=True):
                s = line.split("#", 1)[0].strip()
                m = re.match(r"^DocumentRoot\s+['\"]?([^'\"\s]+)", s, re.I)
                if not m:
                    m = re.match(r"^Alias\s+\S+\s+['\"]?([^'\"\s]+)", s, re.I)
                if m:
                    found.append(m.group(1))
        roots = []
        for r in sorted({posixpath.normpath(r) for r in found if r.startswith("/")}):
            if ctx.stat(r, follow=True) is None:
                continue
            if any(r == x or r.startswith(x + "/") for x in roots):
                continue  # 이미 찾은 웹 루트 안쪽이면 다시 훑지 않는다
            roots.append(r)
        return roots

    def walk(self, ctx, root, denied):
        stack = [root]
        while stack:
            logical = stack.pop()
            try:
                entries = sorted(os.scandir(ctx.path(logical)), key=lambda e: e.name)
            except PermissionError:
                denied.append(logical)
                continue
            except (FileNotFoundError, NotADirectoryError):
                continue
            for entry in entries:
                child = posixpath.join(logical, entry.name)
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode):
                    stack.append(child)
                elif stat.S_ISREG(st.st_mode) and ext_of(child) in SCRIPT_EXT | IMAGE_EXT:
                    yield child, st

    # --- 판정 ---

    def check_file(self, ctx, path, st):
        if st.st_size > MAX_BYTES:
            return None
        self.files_checked += 1
        data = ctx.read_head(path, MAX_BYTES)
        ext = ext_of(path)
        critical, warning, hits = [], [], []

        if ext in IMAGE_EXT:
            m = IMAGE_PHP.search(data)
            if m:
                critical.append("이미지 확장자 파일 안에 PHP 코드가 있다 (업로드 검사 우회)")
                text = data.decode("utf-8", "replace")
                hits.append(self.hit(text, m.start(), m.end() + 40))
        else:
            text = data.decode("utf-8", "replace")
            lower = text.lower()
            if not any(w in lower for w in QUICK_WORDS):
                code, ticks, patterns = "", [], []
            elif ext in PHP_EXT:
                # 위치가 원문과 같으므로 검사는 code로, 근거는 원문(text)으로 보여준다
                code, ticks = php_code(text)
                patterns = [p for k, p in enumerate(REQ_TO_EXEC) if k != 1]
            else:
                code, ticks, patterns = text, [], REQ_TO_EXEC
            req = None
            for pattern in patterns:
                m = pattern.search(code)
                if m:
                    req = (m.start(), m.end())
                    break
            if req is None:
                for a, b in ticks:
                    if REQUEST_RE.search(code, a, b):
                        req = (a, b)
                        break
            if req:
                critical.append("요청 값이 실행 함수로 바로 들어간다")
                hits.append(self.hit(text, *req))
            m = DECODE_EXEC.search(code)
            if m:
                critical.append("인코딩을 풀어 바로 실행한다")
                hits.append(self.hit(text, m.start(), m.end()))
            if not critical:
                m = LONG_DECODE.search(code)
                if m:
                    warning.append("긴 인코딩 문자열을 풀어 쓰는 코드가 있다 (난독화)")
                    hits.append(self.hit(text, m.start(), m.end()))
            parts = path.split("/")[:-1]
            if any(p in UPLOAD_DIRS for p in parts) and not (ext in PHP_EXT and is_empty_php(text)):
                warning.append("업로드 폴더 안에 스크립트 파일이 있다")

        if not critical and not warning:
            return None
        evidence = [Evidence(path, "{}행: {}".format(no, snip)) for no, snip in hits[:3]]
        evidence += [
            Evidence(path, "SHA-256: {}".format(ctx.sha256(path) or "계산 불가")),
            Evidence(path, "소유자 UID {}, 권한 {}".format(st.st_uid, stat.filemode(st.st_mode))),
            Evidence(path, "내용 변경(mtime): {}".format(timefmt.describe(st.st_mtime, ctx.now)[0])),
            Evidence(path, "속성 변경(ctime): {}".format(timefmt.describe(st.st_ctime, ctx.now)[0])),
        ]
        return self.finding(
            reason="{}: {}".format(path, "; ".join(critical + warning)),
            next_steps="파일을 지우기 전에 복사해 보존하고, 웹 서버 접근 로그에서 이 파일 경로로 들어온 요청"
                       "(IP, 시각, 파라미터)을 찾는다. 파일이 생긴 시각(ctime) 전후의 업로드·로그인 기록을 확인한다.",
            evidence=evidence,
            severity="critical" if critical else "warning",
        )

    @staticmethod
    def hit(text, start, end):
        return text.count("\n", 0, start) + 1, snippet(text, start, end)
