#!/bin/bash
# CTF Web Toolkit - macOS 构建脚本
# 生成 dist/ctf-toolkit（单文件可执行）

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== CTF Web Toolkit macOS 构建 ==="
echo "架构: $(uname -m)  系统: $(uname -s)"

# ── 1. 检查/创建虚拟环境 ──────────────────────
if [ ! -d ".venv" ]; then
    echo "[*] 创建虚拟环境..."
    python3 -m venv .venv
fi

PYTHON=".venv/bin/python"
PIP=".venv/bin/pip"

# ── 2. 安装依赖 ───────────────────────────────
echo "[*] 安装依赖..."
$PIP install -q -r requirements.txt
$PIP install -q pyinstaller pyinstaller-hooks-contrib

# ── 3. 清理旧构建 ─────────────────────────────
rm -rf dist/ctf-toolkit build/__pycache__
echo "[*] 清理旧构建完成"

# ── 4. 构建（通用 Fat Binary 优先，否则当前架构）──
ARCH=$(uname -m)
if [ "$1" == "universal" ] || [ "$1" == "fat" ]; then
    echo "[*] 构建 Universal Binary (arm64 + x86_64)..."
    # 需要两种架构的 Python 都已安装
    $PYTHON -m PyInstaller ctf_toolkit.spec \
        --clean --noconfirm \
        --target-arch universal2
else
    echo "[*] 构建当前架构 ($ARCH)..."
    $PYTHON -m PyInstaller ctf_toolkit.spec \
        --clean --noconfirm
fi

# ── 5. 验证 ───────────────────────────────────
if [ -f "dist/ctf-toolkit" ]; then
    echo ""
    echo "[+] 构建成功: dist/ctf-toolkit"
    echo "[+] 大小: $(du -sh dist/ctf-toolkit | cut -f1)"
    echo "[+] 架构: $(file dist/ctf-toolkit | grep -o 'arm64\|x86_64\|universal')"
    echo ""
    echo "=== 测试运行 ==="
    ./dist/ctf-toolkit --help | head -5
    echo ""
    echo "使用方法："
    echo "  ./dist/ctf-toolkit scan http://target.com"
    echo "  ./dist/ctf-toolkit sqli http://target.com --param id"
    echo "  ./dist/ctf-toolkit xxe http://target.com --action detect"
else
    echo "[-] 构建失败！检查上方错误信息"
    exit 1
fi

# ── 6. 可选：打包为 .tar.gz ──────────────────
if [ "$1" == "package" ] || [ "$2" == "package" ]; then
    VERSION=$(date +%Y%m%d)
    ARCH_LABEL=$(uname -m)
    TARBALL="dist/ctf-toolkit-macos-${ARCH_LABEL}-${VERSION}.tar.gz"
    tar -czf "$TARBALL" -C dist ctf-toolkit
    echo "[+] 打包完成: $TARBALL"
fi
