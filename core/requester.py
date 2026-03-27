"""
CTF Web Toolkit - Core HTTP Requester
统一的 HTTP 请求管理器，支持代理、自定义 Header、Session 复用
"""

import requests
import urllib3
from urllib.parse import urljoin, urlparse
from typing import Optional, Dict, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Connection": "keep-alive",
}


class Requester:
    def __init__(
        self,
        base_url: str = "",
        proxy: Optional[str] = None,
        cookies: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: int = 10,
        verify_ssl: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()

        # 设置默认 Headers
        self.session.headers.update(DEFAULT_HEADERS)
        if headers:
            self.session.headers.update(headers)

        # 设置代理
        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy,
            }

        # 设置 Cookies
        if cookies:
            self.session.cookies.update(cookies)

        self._history: list = []

    def get(self, path: str = "", params: Optional[Dict] = None, **kwargs) -> requests.Response:
        url = self._build_url(path)
        resp = self.session.get(url, params=params, timeout=self.timeout,
                                verify=self.verify_ssl, **kwargs)
        self._record(resp)
        return resp

    def post(self, path: str = "", data: Any = None, json: Any = None,
             params: Optional[Dict] = None, **kwargs) -> requests.Response:
        url = self._build_url(path)
        resp = self.session.post(url, data=data, json=json, params=params,
                                 timeout=self.timeout, verify=self.verify_ssl, **kwargs)
        self._record(resp)
        return resp

    def put(self, path: str = "", data: Any = None, json: Any = None, **kwargs) -> requests.Response:
        url = self._build_url(path)
        resp = self.session.put(url, data=data, json=json, timeout=self.timeout,
                                verify=self.verify_ssl, **kwargs)
        self._record(resp)
        return resp

    def raw(self, method: str, url: str, **kwargs) -> requests.Response:
        """直接发送任意 URL 的请求，不拼接 base_url"""
        resp = self.session.request(method.upper(), url, timeout=self.timeout,
                                    verify=self.verify_ssl, **kwargs)
        self._record(resp)
        return resp

    def set_cookie(self, name: str, value: str):
        self.session.cookies.set(name, value)

    def set_header(self, name: str, value: str):
        self.session.headers[name] = value

    def _build_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return urljoin(self.base_url + "/", path.lstrip("/")) if self.base_url else path

    def _record(self, resp: requests.Response):
        self.history.append({
            "method": resp.request.method,
            "url": resp.url,
            "status": resp.status_code,
            "length": len(resp.content),
        })

    @property
    def history(self):
        return self._history

    def print_history(self):
        for i, r in enumerate(self._history):
            print(f"  [{i+1}] {r['method']} {r['url']} -> {r['status']} ({r['length']} bytes)")
