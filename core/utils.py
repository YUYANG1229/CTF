"""
CTF Web Toolkit - Core Utilities
通用辅助函数：编解码、字符串处理、输出美化
"""

import base64
import hashlib
import html
import json
import re
import urllib.parse
from typing import Any, Optional
from colorama import Fore, Style, init

init(autoreset=True)


# ──────────────────────────────────────────────
# 输出美化
# ──────────────────────────────────────────────

def banner():
    print(Fore.CYAN + r"""
  ___  _____ _____   __      __   _     _____           _ _    _ _
 / __||_   _|  ___|  \ \    / /__| |__ |_   _|__   ___ | | | _(_) |_
| (__   | | | |_      \ \/\/ / _ \ '_ \  | |/ _ \ / _ \| | |/ / | __|
 \___|  |_| |_|        \_/\_/\___/_.__/  |_|\___/ \___/|_|_|\_\_|\__|
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + "  CTF Web Security Toolkit  |  Offensive & Defensive" + Style.RESET_ALL)
    print(Fore.WHITE + "  " + "─" * 52 + Style.RESET_ALL + "\n")


def ok(msg: str):
    print(Fore.GREEN + f"  [+] {msg}" + Style.RESET_ALL)


def info(msg: str):
    print(Fore.CYAN + f"  [*] {msg}" + Style.RESET_ALL)


def warn(msg: str):
    print(Fore.YELLOW + f"  [!] {msg}" + Style.RESET_ALL)


def err(msg: str):
    print(Fore.RED + f"  [-] {msg}" + Style.RESET_ALL)


def found(label: str, value: str):
    print(Fore.GREEN + f"  [FOUND] " + Style.RESET_ALL + f"{label}: " + Fore.MAGENTA + value + Style.RESET_ALL)


def section(title: str):
    pad = max(0, 45 - len(title))
    print(Fore.CYAN + f"\n  ── {title} " + "─" * pad + Style.RESET_ALL)


# ──────────────────────────────────────────────
# 编解码工具
# ──────────────────────────────────────────────

def b64_encode(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def b64_decode(s: str) -> str:
    # 补齐 padding
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode(errors="replace")


def b64_decode_bytes(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def url_encode(s: str, safe: str = "") -> str:
    return urllib.parse.quote(s, safe=safe)


def url_decode(s: str) -> str:
    return urllib.parse.unquote(s)


def double_url_encode(s: str) -> str:
    return url_encode(url_encode(s))


def html_encode(s: str) -> str:
    return html.escape(s)


def html_decode(s: str) -> str:
    return html.unescape(s)


def hex_encode(s: str) -> str:
    return s.encode().hex()


def hex_decode(s: str) -> str:
    return bytes.fromhex(s).decode(errors="replace")


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def sha1(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def rot13(s: str) -> str:
    result = []
    for c in s:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)


def to_unicode_escape(s: str) -> str:
    return s.encode('unicode_escape').decode()


def from_unicode_escape(s: str) -> str:
    return s.encode().decode('unicode_escape')


# ──────────────────────────────────────────────
# 字符串 / 正则工具
# ──────────────────────────────────────────────

def extract_flags(text: str, prefix: str = "flag") -> list:
    """从响应体中提取 flag{...} 格式的 flag"""
    pattern = rf"{re.escape(prefix)}\{{[^}}]+\}}"
    return re.findall(pattern, text, re.IGNORECASE)


def extract_between(text: str, start: str, end: str) -> list:
    """提取两个标记之间的所有内容"""
    pattern = re.escape(start) + r"(.*?)" + re.escape(end)
    return re.findall(pattern, text, re.DOTALL)


def grep_response(text: str, keyword: str, context: int = 50) -> list:
    """在响应文本中搜索关键词，返回带上下文的片段"""
    results = []
    for m in re.finditer(re.escape(keyword), text, re.IGNORECASE):
        start = max(0, m.start() - context)
        end = min(len(text), m.end() + context)
        results.append(text[start:end])
    return results


def is_json(text: str) -> bool:
    try:
        json.loads(text)
        return True
    except Exception:
        return False


def pretty_json(text: str) -> Optional[str]:
    try:
        return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
    except Exception:
        return None


def load_wordlist(path: str) -> list:
    """从文件加载字典，忽略空行和 # 注释"""
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        err(f"字典文件不存在: {path}")
        return []


def diff_responses(resp1: str, resp2: str) -> dict:
    """比较两个响应的差异（用于盲注判断）"""
    return {
        "length_diff": abs(len(resp1) - len(resp2)),
        "same_length": len(resp1) == len(resp2),
        "identical": resp1 == resp2,
    }
