# CTF Web Toolkit - Makefile
# 使用：make <target>

PYTHON   := .venv/bin/python
PIP      := .venv/bin/pip
DIST     := dist/ctf-toolkit
VERSION  := $(shell date +%Y%m%d)

.PHONY: all venv deps build build-fat package clean test help

## 默认：安装依赖 + 构建当前平台
all: deps build

## 创建虚拟环境
venv:
	python3 -m venv .venv
	$(PIP) install --upgrade pip

## 安装所有依赖（含 PyInstaller）
deps: venv
	$(PIP) install -q -r requirements.txt
	$(PIP) install -q pyinstaller pyinstaller-hooks-contrib

## 构建当前平台二进制（macOS arm64 / x64）
build: deps
	$(PYTHON) -m PyInstaller ctf_toolkit.spec --clean --noconfirm
	@echo ""
	@echo "构建完成: $(DIST)"
	@ls -lh $(DIST)

## 构建 macOS Universal Binary（arm64 + x86_64）
build-fat: deps
	$(PYTHON) -m PyInstaller ctf_toolkit.spec --clean --noconfirm \
	    --target-arch universal2
	@mv dist/ctf-toolkit dist/ctf-toolkit-universal
	@echo "构建完成: dist/ctf-toolkit-universal"

## 打包为 .tar.gz
package: build
	@ARCH=$$(uname -m); \
	tar -czf dist/ctf-toolkit-macos-$$ARCH-$(VERSION).tar.gz -C dist ctf-toolkit; \
	echo "打包完成: dist/ctf-toolkit-macos-$$ARCH-$(VERSION).tar.gz"

## 测试二进制
test:
	$(DIST) encode "test" --action all
	$(DIST) webshell --action list

## 清理构建产物
clean:
	rm -rf dist build __pycache__ *.spec.bak
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -delete

## 显示帮助
help:
	@echo "CTF Web Toolkit 构建命令："
	@echo "  make            - 安装依赖 + 构建（推荐）"
	@echo "  make build      - 构建当前平台可执行文件"
	@echo "  make build-fat  - 构建 macOS Universal Binary"
	@echo "  make package    - 打包为 .tar.gz"
	@echo "  make test       - 测试已构建的二进制"
	@echo "  make clean      - 清理构建产物"
	@echo ""
	@echo "Windows 构建："
	@echo "  双击运行 build_windows.bat"
	@echo ""
	@echo "跨平台自动构建："
	@echo "  git tag v1.0.0 && git push --tags"
	@echo "  （GitHub Actions 自动构建 macOS/Windows/Linux）"
