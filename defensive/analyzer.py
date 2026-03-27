"""
CTF Web Toolkit - Defensive Analyzer
请求/响应分析、安全头检测、WAF 识别、信息泄露扫描
"""

import re
from typing import Optional, Dict, List
from core.requester import Requester
from core.utils import ok, info, warn, err, found, section

# ── 安全响应头 ────────────────────────────────
SECURITY_HEADERS = {
    "Content-Security-Policy":        "防止 XSS / 数据注入攻击",
    "X-Content-Type-Options":         "防止 MIME 类型嗅探",
    "X-Frame-Options":                "防止点击劫持",
    "X-XSS-Protection":               "浏览器内置 XSS 过滤",
    "Strict-Transport-Security":      "强制 HTTPS (HSTS)",
    "Referrer-Policy":                "控制 Referer 信息泄露",
    "Permissions-Policy":             "控制浏览器功能权限",
    "Cross-Origin-Embedder-Policy":   "跨域嵌入策略",
    "Cross-Origin-Opener-Policy":     "跨域打开策略",
    "Cross-Origin-Resource-Policy":   "跨域资源策略",
}

# ── 信息泄露关键词 ────────────────────────────
INFO_LEAK_PATTERNS = {
    "SQL 错误":     [r"you have an error in your sql", r"ora-\d+", r"pg_query", r"sqlstate"],
    "Stack Trace":  [r"traceback \(most recent", r"at .+\.java:\d+", r"\.php on line \d+",
                     r"exception in thread", r"unhandled exception"],
    "路径泄露":     [r"/var/www/", r"/home/\w+/", r"c:\\inetpub", r"d:\\wwwroot",
                     r"/usr/local/", r"app_root"],
    "内部 IP":      [r"\b10\.\d+\.\d+\.\d+\b", r"\b192\.168\.\d+\.\d+\b",
                     r"\b172\.(1[6-9]|2\d|3[01])\.\d+\.\d+\b", r"\b127\.\d+\.\d+\.\d+\b"],
    "Git 信息":     [r"\.git/", r"commit [0-9a-f]{40}", r"branch: master"],
    "敏感文件":     [r"phpinfo\(\)", r"\[php\]", r"DB_PASSWORD", r"database_url",
                     r"secret_key", r"api_key"],
    "版本信息":     [r"apache/[\d.]+", r"nginx/[\d.]+", r"php/[\d.]+",
                     r"express/[\d.]+", r"tomcat/[\d.]+"],
    "Token/Key":    [r"['\"]?token['\"]?\s*[:=]\s*['\"][a-zA-Z0-9+/=._-]{16,}['\"]",
                     r"['\"]?api_key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9+/=._-]{16,}['\"]",
                     r"['\"]?secret['\"]?\s*[:=]\s*['\"][a-zA-Z0-9+/=._-]{16,}['\"]"],
}

# ── WAF 特征指纹 ──────────────────────────────
WAF_FINGERPRINTS = {
    "Cloudflare":   {"headers": ["cf-ray", "cf-cache-status"], "body": ["cloudflare"]},
    "AWS WAF":      {"headers": ["x-amzn-requestid", "x-amz-cf-id"], "body": []},
    "ModSecurity":  {"headers": ["x-mod-security-message"], "body": ["mod_security", "modsecurity"]},
    "F5 BIG-IP":    {"headers": ["x-cnection", "x-wa-info"], "body": ["reference id:", "big-ip"]},
    "Akamai":       {"headers": ["x-akamai-transformed", "akamai-origin-hop"], "body": []},
    "Imperva":      {"headers": ["x-iinfo", "x-cdn"], "body": ["incapsula", "_incapsula_"]},
    "Sucuri":       {"headers": ["x-sucuri-id", "x-sucuri-cache"], "body": ["sucuri"]},
    "Nginx WAF":    {"headers": [], "body": ["<html>\n<head><title>400 bad request</title>"]},
    "阿里云 WAF":   {"headers": ["x-safe-info"], "body": ["ali-cdn", "tengine"]},
    "华为云 WAF":   {"headers": ["x-request-id"], "body": ["hwcloudwaf"]},
}


class SecurityAnalyzer:
    def __init__(self, requester: Requester):
        self.req = requester

    def analyze_headers(self, url: str) -> dict:
        """分析响应头安全配置"""
        section(f"安全头分析: {url}")
        resp = self.req.get(url)
        if not resp:
            err("请求失败")
            return {}

        result = {
            "missing": [],
            "present": [],
            "server": resp.headers.get("Server", ""),
            "x_powered_by": resp.headers.get("X-Powered-By", ""),
        }

        # 检查安全头
        for header, desc in SECURITY_HEADERS.items():
            if header.lower() in {k.lower() for k in resp.headers}:
                ok(f"  [存在] {header}")
                result["present"].append(header)
            else:
                warn(f"  [缺失] {header} - {desc}")
                result["missing"].append(header)

        # 信息泄露头
        if result["server"]:
            warn(f"  Server 头泄露: {result['server']}")
        if result["x_powered_by"]:
            warn(f"  X-Powered-By 泄露: {result['x_powered_by']}")

        # Cookie 安全属性
        self._check_cookies(resp)

        score = len(result["present"]) / len(SECURITY_HEADERS) * 100
        info(f"  安全头得分: {score:.0f}% ({len(result['present'])}/{len(SECURITY_HEADERS)})")
        return result

    def _check_cookies(self, resp):
        """检查 Cookie 安全属性"""
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("缺少 Secure 标志")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("缺少 HttpOnly 标志")
            samesite = cookie.get_nonstandard_attr("SameSite", "")
            if not samesite:
                issues.append("缺少 SameSite 属性")
            if issues:
                warn(f"  Cookie [{cookie.name}] 问题: {', '.join(issues)}")
            else:
                ok(f"  Cookie [{cookie.name}] 安全配置正常")

    def detect_waf(self, url: str) -> Optional[str]:
        """检测 WAF 类型"""
        section("WAF 检测")
        # 发送明显恶意 payload 触发 WAF
        waf_trigger = "?q=<script>alert(1)</script>&id=1' OR '1'='1"
        resp = self.req.get(url + waf_trigger)
        if not resp:
            return None

        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        body_lower = resp.text.lower()

        for waf, fp in WAF_FINGERPRINTS.items():
            header_match = any(h in headers_lower for h in fp["headers"])
            body_match = any(b in body_lower for b in fp["body"])
            if header_match or body_match:
                found("WAF", waf)
                return waf

        # 通过状态码判断
        if resp.status_code == 403:
            warn("  返回 403，可能存在 WAF/规则过滤")
            return "unknown_waf"
        elif resp.status_code == 406:
            warn("  返回 406 Not Acceptable，可能有 WAF")
            return "unknown_waf"

        info("未检测到已知 WAF")
        return None

    def scan_info_leak(self, url: str) -> dict:
        """扫描响应中的信息泄露"""
        section("信息泄露扫描")
        resp = self.req.get(url)
        if not resp:
            return {}

        result = {}
        text = resp.text

        for category, patterns in INFO_LEAK_PATTERNS.items():
            matches = []
            for pattern in patterns:
                for m in re.finditer(pattern, text, re.IGNORECASE):
                    matches.append(m.group()[:100])
            if matches:
                found(category, matches[0])
                result[category] = matches

        # 检查响应头
        for h, v in resp.headers.items():
            for category, patterns in INFO_LEAK_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, f"{h}: {v}", re.IGNORECASE):
                        warn(f"  响应头信息泄露 [{h}]: {v}")

        return result

    def scan_common_paths(self, base_url: str, paths: Optional[List[str]] = None) -> List[dict]:
        """扫描常见敏感路径"""
        section("敏感路径探测")
        if paths is None:
            paths = COMMON_PATHS

        results = []
        for path in paths:
            resp = self.req.get(f"{base_url.rstrip('/')}/{path.lstrip('/')}")
            if resp and resp.status_code in [200, 301, 302, 403, 401]:
                entry = {
                    "path": path,
                    "status": resp.status_code,
                    "length": len(resp.text),
                }
                if resp.status_code == 200:
                    found("路径", f"{path} ({resp.status_code}, {len(resp.text)} bytes)")
                else:
                    info(f"  {path} -> {resp.status_code}")
                results.append(entry)
        return results

    def analyze_response(self, resp) -> dict:
        """深度分析单个响应"""
        section("响应分析")
        if not resp:
            return {}

        result = {
            "status": resp.status_code,
            "content_type": resp.headers.get("Content-Type", ""),
            "length": len(resp.text),
            "encoding": resp.encoding,
            "redirect": resp.url != resp.request.url if resp.request else False,
        }

        info(f"  状态码: {resp.status_code}")
        info(f"  Content-Type: {result['content_type']}")
        info(f"  响应长度: {result['length']}")

        # 检测 JSON 响应
        if "json" in result["content_type"]:
            try:
                data = resp.json()
                info(f"  JSON 结构: {list(data.keys()) if isinstance(data, dict) else type(data).__name__}")
            except Exception:
                pass

        # 提取注释
        comments = re.findall(r"<!--(.*?)-->", resp.text, re.DOTALL)
        for c in comments[:5]:
            c = c.strip()
            if len(c) > 3:
                warn(f"  HTML 注释: {c[:100]}")

        # 提取隐藏表单字段
        hidden = re.findall(r'<input[^>]+type=["\']hidden["\'][^>]*>', resp.text, re.IGNORECASE)
        for h in hidden:
            info(f"  隐藏字段: {h[:150]}")

        return result

    def full_audit(self, url: str) -> dict:
        """执行完整安全审计"""
        section(f"完整审计: {url}")
        return {
            "headers":   self.analyze_headers(url),
            "waf":       self.detect_waf(url),
            "info_leak": self.scan_info_leak(url),
            "paths":     self.scan_common_paths(url),
        }


# ── 常见敏感路径 ──────────────────────────────
COMMON_PATHS = [
    ".git/HEAD", ".git/config", ".svn/entries", ".DS_Store",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "/.env", "/.env.local", "/.env.backup",
    "/config.php", "/config.yml", "/config.json", "/settings.py",
    "/admin", "/admin/", "/admin.php", "/administrator",
    "/wp-admin", "/wp-login.php", "/wp-config.php",
    "/phpinfo.php", "/info.php", "/test.php",
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/api/swagger.json", "/api/v1/docs", "/swagger-ui.html",
    "/actuator", "/actuator/env", "/actuator/heapdump",
    "/console", "/h2-console", "/adminer.php",
    "/.well-known/security.txt",
    "/server-status", "/server-info",
    "/debug", "/trace",
]
