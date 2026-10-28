#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sub-pool-builder · 把 sub-server Worker v10 的「抓上游 → 探活 → 合成订阅」搬到 GitHub Actions.

动机（见 tasks/审查-sub-server-v10-20261016.md §二）：Workers 免费档 50 子请求/10ms CPU
做不了真协议握手探活，只能拿「明文 http://IP:443 回 400」当存活判据 —— 实测非 CF 源站
同样回 400，会被整批判成活。Actions runner 没有该限制，所以这里做**三层真探活**：

    ① TCP connect(候选自带端口, 4s)  →  ② TLS handshake(SNI=后端域名)  →  ③ WS Upgrade(节点自身 Host+path)

只有 ③ 拿到 HTTP/1.1 101 才算活。三层全部针对**该节点真实要用的组合**
(server=优选 IP, port=候选自带端口, SNI/Host/path=base 里那条 ws 后端)。

凭据纪律（红线）：本文件零凭据。CF_API_TOKEN / CFYES_KEY / SUB_USERINFO 一律只从环境变量读，
任何日志/异常文本都先过 redact() 过滤，绝不打印 Authorization 头、token、订阅 URL、KV userinfo 原文。

KV 值形状写死为 {"yaml": <配置JSON文本字符串>, "userinfo": <空格分隔原样串>}；写错 Worker 直接 404。
S1–S5 阶段只写影子 key（--kv-prefix 默认 "test:"），真 key 只在显式 --promote 时写。

用法：
    python3 build.py --dry-run                 # 全程不联网，用内置样本验证配额/去重
    python3 build.py                           # 抓取+探活+合成，写影子 key（需 secret）
    python3 build.py --promote                 # 额外把终版复制进真 key sub:<token>（验收通过后）

Python 3.11+ 标准库，无第三方依赖。
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import random
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# =====================================================================
# 1) 常量：家族配额 / 上游源清单（全部照搬 v10，一条不增不减、不自创）
# =====================================================================

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "Chrome/126 Safari/537.36")

# FAMILY_TARGET 记的是**最终节点数**（bug #4 口径：每个 IP 产 2 节点，故 IP 槽位上限 = ceil(target/2)）。
FAMILY_TARGET = {
    "新加坡": 22, "麒麟优选": 20, "香港": 20, "日本": 18, "微测优选": 18, "港岛茶记": 18,
    "移动": 10, "电信": 8, "小日本儿": 4, "韩国": 4, "洛璃优选": 2, "阿联酋": 2, "印度": 2, "美国": 2,
}

# 地区 -> 允许生成的家族名（多个则并存，如「香港」与「港岛茶记」）。全部是 FAMILY_TARGET 里的标准名。
REGION_FAMILIES = {
    "日本": ["日本", "小日本儿"], "香港": ["香港", "港岛茶记"],
    "美国": ["美国"], "新加坡": ["新加坡"], "韩国": ["韩国"],
    "阿联酋": ["阿联酋"], "印度": ["印度"],
}
BRAND_FAMILIES = {"麒麟优选", "洛璃优选", "微测优选"}
ISP_FAMILIES = {"移动": "移动", "电信": "电信"}

# ⛔ bug #1 修复要点：家族名一律从 FAMILY_TARGET 取，任何分支都不许写标准表外的花名。
# v10 的 ONLY_US=true 分支写死 add("战争贩子", ...)，而「战争贩子」不在 FAMILY_TARGET ⇒ 回退
# cap=FAMILY_CAP*2=120 个 IP=240 节点，直接打爆配额。这里 ONLY_US 只作过滤条件，落到的家族名恒为「美国」。
ONLY_US_FALLBACK_FAMILY = "美国"
FAMILY_CAP = 60  # 仅用于「白名单外家族」的兜底口径；add() 已拒绝白名单外家族，实际不会用到

# ---- 探活参数（任务书 §4-S2 + 审查文 §二） ----
PROBE_TIMEOUT = 4.0            # 单层超时（秒）；TCP/TLS/WS 各自不超过它
PROBE_CONCURRENCY = 50         # 并发上限 ≤50
PROBE_RETRIES = 1              # 单 IP 失败重试 1 次
PROBE_MIN_PASSES = 2           # 一个候选探到 2 条后端即够（主节点 + X 变体各一条），命中后短路
PROBE_CANDIDATE_DEADLINE = 25.0
ALIVE_MIN_RATIO = 0.30         # 聚合存活率 <30% ⇒ 判源面故障：不写 KV、退出码非 0
NON_STANDARD_PORTS = (2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8443)  # bug #5：这些端口以前全被按 443 探

SHRINK_GUARD_RATIO = 0.70      # 新配置节点数 ≥ 上一版 70% 才允许写
# ⚠ 口径澄清（本轮验收时核过 v10 源码第 41-47 行）：`profile-update-interval` **不是订阅配置里的字段**，
# 而是 Worker fetch 处理器返回的 HTTP 响应头 ⇒ 改 1→6 这件事发生在 S6 的 Worker 补丁里，不在本文件。
# 这里只保留一个「期望值」用于 meta 记录与 S6 补丁对账，⛔ 不会写进合成的 yaml。
PROFILE_UPDATE_INTERVAL = "6"  # 与 6h cron 对齐的期望值（S6 落到 Worker 响应头）

KV_BINDING_NAME = "SUB_KV"             # Worker 绑定名
KV_NAMESPACE_TITLE = "sub-server-SUB_KV"
CF_API_BASE = "https://api.cloudflare.com/client/v4"

COLO_MAP = {
    "HKG": "香港", "SIN": "新加坡", "NRT": "日本", "KIX": "日本", "HND": "日本", "ICN": "韩国",
    "LAX": "美国", "SJC": "美国", "SFO": "美国", "SEA": "美国", "ORD": "美国", "DFW": "美国",
    "IAD": "美国", "MIA": "美国", "EWR": "美国", "MSP": "美国", "ATL": "美国", "DEN": "美国",
    "PHX": "美国", "SLC": "美国", "YYZ": "加拿大", "YVR": "加拿大", "LHR": "英国", "FRA": "德国",
    "AMS": "荷兰", "CDG": "法国", "SVO": "俄罗斯", "DME": "俄罗斯", "SYD": "澳大利亚",
    "MEL": "澳大利亚", "AKL": "新西兰", "BOM": "印度", "MAA": "印度", "DEL": "印度",
    "BKK": "泰国", "KUL": "马来西亚", "MNL": "菲律宾", "CGK": "印尼", "HAN": "越南",
    "SGN": "越南", "GRU": "巴西", "MEX": "墨西哥", "EZE": "阿根廷", "SCL": "智利",
    "BOG": "哥伦比亚", "JNB": "南非", "DXB": "阿联酋", "TLV": "以色列", "IST": "土耳其",
    "WAW": "波兰", "ARN": "瑞典", "ZRH": "瑞士", "MXP": "意大利", "MAD": "西班牙",
    "VIE": "奥地利", "RIX": "拉脱维亚", "LGG": "比利时",
}
REGION_CODE = {
    "HK": "香港", "MO": "澳门", "TW": "台湾", "JP": "日本", "KR": "韩国", "SG": "新加坡",
    "US": "美国", "GB": "英国", "UK": "英国", "DE": "德国", "FR": "法国", "NL": "荷兰",
    "RU": "俄罗斯", "CA": "加拿大", "AU": "澳大利亚", "TR": "土耳其", "MY": "马来西亚",
    "VN": "越南", "PH": "菲律宾", "TH": "泰国", "IN": "印度", "ID": "印尼", "AE": "阿联酋",
}
# 标准地区 → 花名。v10 用它生成家族名（日本→小日本儿、香港→港岛茶记），这里保留同一份映射，
# 但**只有落在 FAMILY_TARGET 里的花名才会成为家族**（其余在 add() 处被丢弃）。
FUN_NAMES = {
    "日本": "小日本儿", "香港": "港岛茶记", "新加坡": "印加坡县", "台湾": "宝岛正妹",
    "美国": "战争贩子", "德国": "元首复活", "英国": "大嘤帝国", "俄罗斯": "战斗毛子",
    "马来西亚": "大马榴莲", "越南": "西贡咖啡", "菲律宾": "菲氏叶猴", "泰国": "萨瓦迪卡",
    "印度": "干净卫生", "法国": "每日乳法", "加拿大": "枫叶之国", "土耳其": "烤肉火鸡",
    "澳大利亚": "土澳袋鼠", "荷兰": "风车郁金", "韩国": "泡菜欧巴",
}
# 家族花名/标准名 -> 标准地区（给生成节点名补 "(地区)" 后缀）
REGION_OF_FUN = {v: k for k, v in FUN_NAMES.items()}
REGION_OF_FUN.update({k: k for k in
                      ("美国", "日本", "香港", "新加坡", "韩国", "阿联酋", "印度", "台湾")})
ISP_MAP = {"CM": "移动", "CU": "联通", "CT": "电信", "CMCC": "移动", "CTCC": "电信", "CUCC": "联通"}

GSLEGE = "https://raw.githubusercontent.com/gslege/CloudflareIP/refs/heads/main/{r}.txt"
# v10：ONLY_US=true 时只拉 US.txt；false 时拉 JP/US/SG/DE/NL/Cfxyz 六路。两分支都照搬。
GSLEGE_REGIONS_ALL = ["JP", "US", "SG", "DE", "NL", "Cfxyz"]
GSLEGE_REGIONS_US_ONLY = ["US"]

# 原生 VLESS 真实节点源。v10 置空 = 用户明确要「严格对齐参考订阅数量」，保留该设计意图。
GITHUB_SOURCES: list[str] = []

# =====================================================================
# 2) 日志与脱敏（红线：凭据永不外泄）
# =====================================================================

_SECRETS: list[str] = []


def register_secret(value: str | None) -> None:
    """把敏感值登记进脱敏表（只登记，绝不打印）。短于 6 字符的不登记以免误伤。"""
    if value and len(value) >= 6:
        _SECRETS.append(value)


def _mask_path(path: str) -> str:
    """遮蔽 KV key 路径末段（可能是 sub:<token>），避免 token 被打进公开 Actions 日志。"""
    head, sep, tail = path.rpartition("/")
    return f"{head}{sep}<KEY>" if sep else "<PATH>"


def redact(text: object) -> str:
    s = str(text)
    for secret in _SECRETS:
        s = s.replace(secret, "[REDACTED]")
    # 兜底：订阅 URL 里的 16hex token、Authorization 头、base64 长串
    s = re.sub(r"Authorization\s*[:=]\s*\S+", "Authorization: [REDACTED]", s, flags=re.I)
    s = re.sub(r"/[0-9a-f]{16}/", "/<TOKEN>/", s)
    s = re.sub(r"(key|token|secret|userinfo)[\"']?\s*[:=]\s*[\"']?[^\s\"',}]{6,}",
               r"\1=[REDACTED]", s, flags=re.I)
    return s


def log(*parts: object) -> None:
    print(redact(" ".join(str(p) for p in parts)), flush=True)


def sha256_of(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def mask_key(key: str) -> str:
    """key 名含订阅 token（=凭据），日志只给 sha8 + 前缀。"""
    prefix = key.split(":")[0] if ":" in key else ""
    return f"<{prefix}:…#{hashlib.sha256(key.encode()).hexdigest()[:8]}>"


# =====================================================================
# 3) HTTP 工具（urllib.request；超时 + 脱敏异常）
# =====================================================================

class FetchError(Exception):
    pass


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener()


def http_get_text(url: str, timeout: float = 12.0, headers: dict | None = None) -> str:
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        with _opener().open(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            if status != 200:
                raise FetchError(f"HTTP {status} for {redact(_short_url(url))}")
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raise FetchError(f"HTTP {e.code} for {redact(_short_url(url))}") from None
    except Exception as e:  # socket.timeout / URLError / ConnectionError ...
        raise FetchError(f"{type(e).__name__} for {redact(_short_url(url))}") from None
    return raw.decode("utf-8", errors="replace")


def http_post_json(url: str, payload: dict, timeout: float = 12.0) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with _opener().open(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raise FetchError(f"HTTP {e.code} for {redact(_short_url(url))}") from None
    except Exception as e:
        raise FetchError(f"{type(e).__name__} for {redact(_short_url(url))}") from None
    # 4ce/hostmonit 偶尔包 JSONP 或带 BOM，做一次宽松提取
    text = raw.decode("utf-8", errors="replace").lstrip("\ufeff").strip()
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{[\s\S]*\}", text)
        if not m:
            raise FetchError(f"响应非 JSON for {redact(_short_url(url))}") from None
        return json.loads(m.group(0))


def _short_url(url: str) -> str:
    """异常文本只留 host+path，丢掉 query（可能含 key）。"""
    try:
        p = urllib.parse.urlsplit(url)
        return f"{p.netloc}{p.path}"
    except Exception:
        return "url"


# =====================================================================
# 4) 归一化（照搬 v10 的 detectIsp / normalizeRegion / validIp）
# =====================================================================

_EMOJI_RE = re.compile("[\U0001F000-\U0001FAFF\u2600-\u27BF\U0001F1E6-\U0001F1FF\uFE0F]")
_IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_IP_PORT_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})#(.+)$")
_STOP_TOKENS = {"CF", "VPN", "CDN", "IP", "OK", "MAX", "PRO", "TEST", "NODES"}
_CN_NAMES = ("香港", "台湾", "澳门", "新加坡", "韩国", "日本", "印度", "美国", "德国",
             "荷兰", "英国", "法国", "俄罗斯", "加拿大", "澳大利亚", "土耳其", "马来西亚", "泰国",
             "越南", "菲律宾", "印尼", "阿联酋", "以色列", "巴西", "南非", "瑞典", "瑞士", "意大利",
             "西班牙", "波兰", "奥地利", "智利", "哥伦比亚", "阿根廷", "墨西哥", "新西兰", "中国")


def valid_ip(ip: str) -> bool:
    if not _IPV4_RE.fullmatch(ip or ""):
        return False
    return all(int(x) <= 255 for x in ip.split("."))


def detect_isp(text: str | None) -> str | None:
    if not text:
        return None
    t = str(text).upper()
    if re.search(r"移动|CMCC|CHINA\s*MOBILE", t):
        return "移动"
    if re.search(r"电信|CTCC|CHINA\s*TELECOM", t):
        return "电信"
    if re.search(r"联通|CUCC|CHINA\s*UNICOM", t):
        return "联通"
    for k, v in ISP_MAP.items():
        if k in t:
            return v
    return None


def normalize_region(text: str | None) -> str | None:
    if not text:
        return None
    s = _EMOJI_RE.sub(" ", str(text)).strip()
    if not s or detect_isp(s):
        return None
    for k in FUN_NAMES:              # 先认标准名
        if k in s:
            return k
    for name in _CN_NAMES:
        if name in s:
            return name
    for tok in re.findall(r"[A-Za-z]{2,4}", s):
        t = tok.upper()
        if t in _STOP_TOKENS:
            continue
        if t in COLO_MAP:
            return COLO_MAP[t]
        if t in REGION_CODE:
            return REGION_CODE[t]
    return None


def _split_host_remark(remark: str) -> tuple[str | None, str | None]:
    """v10 口径：remark 用 | 分段，第一段判地区、整串判运营商。"""
    segs = [s.strip() for s in (remark or "").split("|")]
    region = normalize_region(segs[0]) if segs else None
    isp = detect_isp(" ".join(segs)) if segs else None
    return region, isp


# =====================================================================
# 5) 上游抓取：源清单 1:1 照搬 v10（BRAND_SOURCES 7 路 + REGION_SOURCES 9 路）
# =====================================================================
# 返回统一候选 dict：{ip, port, region, isp, brand, source}
# hostmonit/cfyes 的 key 只从环境变量 CFYES_KEY 读 —— ⛔ 不许把 v10 硬编码的 key 抄进来。

def fetch_mirror(url: str, source: str) -> list[dict]:
    """QNAir 格式镜像： IP:port#QNAir-LL | 地区 | 001"""
    text = http_get_text(url)
    out = []
    for line in text.split("\n"):
        m = _IP_PORT_RE.match(line.strip())
        if not m or not valid_ip(m.group(1)):
            continue
        segs = [s.strip() for s in m.group(3).split("|")]
        region = normalize_region(segs[1]) if len(segs) > 1 else None
        isp = detect_isp(segs[1]) if len(segs) > 1 else None
        port = int(m.group(2))
        out.append({"ip": m.group(1), "port": port, "region": region, "isp": isp,
                    "brand": None, "source": source})
    return out


def fetch_gslege(region_code: str, source: str) -> list[dict]:
    url = GSLEGE.format(r=region_code)
    text = http_get_text(url)
    out = []
    for line in text.split("\n"):
        if "#" not in line:
            continue
        head, _, rest = line.partition("#")
        h = head.strip()
        # 单模式可选端口：写成「带端口 or 不带端口」两个 fullmatch 会让 IP-only 行
        # 命中第二个模式（只有 1 个捕获组），随后取 m.group(2) 直接 IndexError。
        m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?", h)
        if not m or not valid_ip(m.group(1)):
            continue
        remark = rest.strip()
        region, isp = _split_host_remark(remark)
        out.append({"ip": m.group(1), "port": int(m.group(2)) if m.group(2) else 443,
                    "region": region, "isp": isp,
                    "brand": None, "source": f"{source}:{region_code}"})
    return out


def fetch_zhixuan(url: str, source: str) -> list[dict]:
    text = http_get_text(url)
    out = []
    for tok in re.split(r"\s+", text.replace(",", " ")):
        m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?", tok)
        if m and valid_ip(m.group(1)):
            out.append({"ip": m.group(1), "port": int(m.group(2)) if m.group(2) else 443,
                        "region": None, "isp": None, "brand": None, "source": source})
    return out


def fetch_nirevil(url: str, source: str) -> list[dict]:
    data = json.loads(http_get_text(url))
    out = []
    for it in (data if isinstance(data, list) else []):
        ip = it.get("ip") if isinstance(it, dict) else None
        if ip and valid_ip(ip):
            out.append({"ip": ip, "port": 443,
                        "region": normalize_region(it.get("colo")), "isp": detect_isp(it.get("line")),
                        "brand": None, "source": source})
    return out


def fetch_cfyes(source: str, key: str) -> list[dict]:
    """api.hostmonit.com —— key 来自 secret CFYES_KEY，⛔ 不落字面值。"""
    if not key:
        raise FetchError("缺少 CFYES_KEY，跳过 hostmonit 源")
    data = http_post_json("https://api.hostmonit.com/get_optimization_ip", {"key": key, "type": "v4"})
    out = []
    for it in (data.get("info") or []):
        ip = it.get("ip") if isinstance(it, dict) else None
        if ip and valid_ip(ip):
            out.append({"ip": ip, "port": 443, "region": None, "isp": detect_isp(it.get("line")),
                        "brand": None, "source": source})
    return out


def fetch_vvhan(source: str) -> list[dict]:
    res = http_get_jsonish("https://api.4ce.cn/api/bestCFIP", source)
    if not res.get("success"):
        raise FetchError("vvhan success=false")
    out = []
    v4 = (res.get("data") or {}).get("v4") or {}
    for key in ("CM", "CU", "CT"):
        for it in (v4.get(key) or []):
            ip = it.get("ip") if isinstance(it, dict) else None
            if ip and valid_ip(ip):
                out.append({"ip": ip, "port": 443, "region": normalize_region(it.get("colo")),
                            "isp": detect_isp(key), "brand": None, "source": f"{source}:{key}"})
    return out


def http_get_jsonish(url: str, source: str) -> dict:
    raw = http_get_text(url)
    raw = raw.lstrip("\ufeff").strip()
    try:
        return json.loads(raw)
    except Exception:
        m = re.search(r"\{[\s\S]*\}", raw)
        if not m:
            raise FetchError(f"{source}: 响应非 JSON")
        return json.loads(m.group(0))


def fetch_wetest(source: str) -> list[dict]:
    html = http_get_text("https://www.wetest.vip/page/cloudflare/address_v4.html")
    cells = [m.group(1).strip() for m in re.finditer(
        r'data-label="(?:线路名称|优选地址|数据中心)"[^>]*>\s*([^<\r\n]+?)\s*<', html)]
    out = []
    for i in range(0, len(cells) - 2, 3):      # 与 v10 的 i+2 < length 完全等价
        ip = cells[i + 1].strip()
        if valid_ip(ip):
            out.append({"ip": ip, "port": 443, "region": normalize_region(cells[i + 2]),
                        "isp": detect_isp(cells[i]), "brand": None, "source": source})
    return out


def fetch_uouin(source: str) -> list[dict]:
    html = http_get_text("https://api.uouin.com/cloudflare.html", timeout=15.0)
    out = []
    for row in re.finditer(r"<tr[^>]*>([\s\S]*?)</tr>", html):
        cells = [re.sub(r"<[^>]+>", "", c).strip()
                 for c in re.findall(r"<td[^>]*>([\s\S]*?)</td>", row.group(1))]
        if len(cells) < 5 or re.search(r"IPv6", cells[0], re.I):
            continue
        m = _IPV4_RE.search(" ".join(cells))
        if m and valid_ip(m.group(0)):
            out.append({"ip": m.group(0), "port": 443, "region": None,
                        "isp": detect_isp(cells[0]), "brand": None, "source": source})
    return out


def build_source_jobs(only_us: bool, cfyes_key: str) -> list[tuple[str, callable]]:
    """源定义照搬 v10 BRAND_SOURCES / REGION_SOURCES（含 ONLY_US 分支），一条不增不减。

    返回 [(统计用源名, 抓取函数)]。品牌源名带 'brand:' 前缀，便于逐源失败计数区分两类源。
    """
    jobs: list[tuple[str, callable]] = []
    if not only_us:
        jobs += [
            ("brand:微测优选/wetest", lambda: fetch_wetest("wetest")),
            ("brand:麒麟优选/uouin", lambda: fetch_uouin("uouin")),
            ("brand:洛璃优选/luoli",
             lambda: fetch_mirror("https://bestcf.pages.dev/luoli/all.txt", "luoli")),
            ("brand:辣子鸡优选/lzj",
             lambda: fetch_mirror("https://bestcf.pages.dev/lzj/all.txt", "lzj")),
            ("brand:Mia优选/mia",
             lambda: fetch_mirror("https://bestcf.pages.dev/xinyitang3/ipv4.txt", "mia")),
            ("brand:CM优选/cmliu", lambda: (
                fetch_mirror("https://bestcf.pages.dev/cmliu/all.txt", "cmliu") +
                fetch_mirror("https://bestcf.pages.dev/cmliu2/all.txt", "cmliu2"))),
            ("brand:ZhiXuan优选/zhixuan", lambda: fetch_zhixuan(
                "https://raw.githubusercontent.com/ZhiXuanWang/cf-speed-dns/main/CloudFlare_ip.txt",
                "zhixuan")),
        ]
    jobs += [
        ("region:hostmonit", lambda: fetch_cfyes("hostmonit", cfyes_key)),
        ("region:vvhan", lambda: fetch_vvhan("vvhan")),
        ("region:nirevil", lambda: fetch_nirevil(
            "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/Cf-ipv4.json",
            "nirevil")),
    ]
    codes = GSLEGE_REGIONS_US_ONLY if only_us else GSLEGE_REGIONS_ALL
    for r in codes:
        jobs.append((f"region:gslege:{r}", (lambda rr=r: fetch_gslege(rr, "gslege"))))
    return jobs


def collect_candidates(only_us: bool, cfyes_key: str, stats: dict) -> list[dict]:
    """抓全部源；单源失败只计数不抛（Actions 出口是数据中心 IP，同源连续失败先怀疑限流≠节点死）。

    品牌源抓到的条目统一打上 brand（与 v10 collectFamilies 的 `{...it, brand: name}` 同口径），
    后面 assign_families 才认得出「微测优选/麒麟优选/洛璃优选」这三个品牌家族。
    """
    candidates: list[dict] = []
    jobs = build_source_jobs(only_us, cfyes_key)

    def run_one(name: str, fn: callable) -> tuple[str, list[dict] | None, str | None]:
        try:
            return name, fn(), None
        except Exception as e:
            return name, None, redact(f"{type(e).__name__}: {str(e)[:160]}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, max(1, len(jobs)))) as ex:
        futs = [ex.submit(run_one, name, fn) for name, fn in jobs]
        for fut in concurrent.futures.as_completed(futs):
            name, items, err = fut.result()
            entry = stats["sources"].setdefault(name, {"ok": err is None, "count": 0, "errors": 0})
            if err is not None:
                entry["ok"] = False
                entry["count"] = 0
                entry["errors"] = entry.get("errors", 0) + 1
                entry["last_error"] = err
                log(f"[源失败] {name}: {err}")
                continue
            entry["ok"] = True
            entry["count"] = len(items or [])
            log(f"[源OK] {name}: {len(items or [])} 条")
            brand = name.split(":", 1)[1].split("/")[0] if name.startswith("brand:") else None
            for it in (items or []):
                if brand and not it.get("brand"):
                    it["brand"] = brand
                candidates.append(it)
    return candidates


def dedup_candidates(candidates: list[dict]) -> list[dict]:
    """bug #3：去重键加端口 ⇒ ip|brand|port。同 IP 的 443 / 2096 两行不再互相吞掉。"""
    seen: set[str] = set()
    uniq = []
    for c in candidates:
        if not c or not c.get("ip") or not valid_ip(c["ip"]):
            continue
        if not (1 <= int(c.get("port") or 443) <= 65535):
            continue
        c["port"] = int(c.get("port") or 443)
        key = f"{c['ip']}|{c.get('brand') or ''}|{c['port']}"   # ← 端口入键
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)
    return uniq


# =====================================================================
# 6) 三层真探活（socket + ssl + asyncio；线程池跑阻塞 IO，信号量限并发 ≤50）
# =====================================================================

class ProbeResult:
    __slots__ = ("ip", "port", "tcp_ok", "passes", "detail", "error", "elapsed")

    def __init__(self, ip: str, port: int):
        self.ip, self.port, self.tcp_ok = ip, port, False
        self.passes: list[int] = []      # 通过三层的 ws_backend 下标
        self.detail: dict[str, str] = {}
        self.error: str | None = None
        self.elapsed = 0.0


def _ws_upgrade_request(host: str, path: str) -> bytes:
    key = base64.b64encode(random.randbytes(16)).decode()
    lines = [f"GET {path or '/'} HTTP/1.1", f"Host: {host}", "Upgrade: websocket",
             "Connection: Upgrade", f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13",
             f"User-Agent: {UA}", "", ""]
    return "\r\n".join(lines).encode()


def _tcp_connect(ip: str, port: int, timeout: float) -> tuple[socket.socket | None, str]:
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        return s, ""
    except Exception as e:
        return None, f"tcp:{type(e).__name__}"


def _tls_handshake(sock: socket.socket, sni: str, timeout: float) -> tuple[ssl.SSLSocket | None, str]:
    # 连的是 CF 优选 IP，证书 CN/SAN 与 IP 不匹配是必然 ⇒ 只能关证书校验，
    # 但 **SNI 必须按后端域名发出**（这正是判活关键：CF 边缘按 SNI 路由到 zone）。
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    try:
        t = sock.gettimeout()
        s = ctx.wrap_socket(sock, server_hostname=sni)
        try:
            s.settimeout(timeout if timeout else t)
        except Exception:
            pass
        return s, ""
    except Exception as e:
        return None, f"tls:{type(e).__name__}:{str(e)[:60]}"


def _ws_upgrade(sock: ssl.SSLSocket, host: str, path: str, timeout: float) -> tuple[bool, str]:
    try:
        sock.sendall(_ws_upgrade_request(host, path))
        deadline = time.monotonic() + timeout
        buf = b""
        while b"\r\n\r\n" not in buf and time.monotonic() < deadline:
            chunk = sock.recv(1024)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 16384:
                break
        head = buf.decode("latin-1", errors="replace")
        status = re.search(r"HTTP/1\.[01]\s+(\d{3})", head)
        if not status:
            return False, "ws:no-response-head"
        code = int(status.group(1))
        if code == 101:
            return True, "101"
        return False, f"ws:{code}"
    except Exception as e:
        return False, f"ws:{type(e).__name__}"


def probe_one_combo_sync(ip: str, port: int, backends: list[dict], timeout: float,
                         retries: int, deadline_after: float,
                         min_passes: int) -> ProbeResult:
    """一个候选 (ip,port) 对全部 ws 后端做三层探活；探到 min_passes 条即短路。

    层级严格递进：TCP 不通 ⇒ 所有后端直接判死（不再浪费时间做 TLS）；
    TLS 失败 ⇒ 该后端记死；WS 非 101 ⇒ 该后端记死。⛔ 绝不用「明文 http 回 400」当存活判据。
    """
    res = ProbeResult(ip, port)
    t0 = time.monotonic()
    sock, tcp_err = _tcp_connect(ip, port, timeout)
    if sock is None:
        if retries > 0 and time.monotonic() < deadline_after:
            time.sleep(0.3)
            sock, tcp_err = _tcp_connect(ip, port, timeout)
    if sock is None:
        res.error = tcp_err or "tcp:fail"
        res.elapsed = time.monotonic() - t0
        return res
    res.tcp_ok = True
    try:
        sock.close()
    except Exception:
        pass

    for idx, be in enumerate(backends):
        if time.monotonic() > deadline_after:
            res.detail[str(idx)] = "skipped:deadline"
            continue
        if len(res.passes) >= min_passes:
            res.detail[str(idx)] = "skipped:short-circuit"
            continue
        server = be.get("server") or ""
        sni = be.get("servername") or server
        host = ((be.get("ws-opts") or {}).get("headers") or {}).get("Host") or sni or server
        path = (be.get("ws-opts") or {}).get("path") or "/"
        attempt, last = 0, "tcp:fail"
        while attempt <= retries:
            attempt += 1
            s, err = _tcp_connect(ip, port, timeout)
            if s is None:
                last = err or "tcp:fail"
                if attempt <= retries:
                    time.sleep(0.3)
                    continue
                break
            tls, err2 = _tls_handshake(s, sni, timeout)
            if tls is None:
                last = err2 or "tls:fail"
                try:
                    s.close()
                except Exception:
                    pass
                if attempt <= retries:
                    time.sleep(0.3)
                    continue
                break
            ok, code = _ws_upgrade(tls, host, path, timeout)
            try:
                tls.close()
            except Exception:
                pass
            if ok:
                res.passes.append(idx)
                last = "101"
                break
            last = code
            if attempt <= retries:
                time.sleep(0.3)
        res.detail[str(idx)] = last
    res.elapsed = time.monotonic() - t0
    return res


async def _probe_async(cands: list[dict], backends: list[dict], timeout: float, retries: int,
                       concurrency: int, candidate_deadline: float, min_passes: int,
                       sim: bool = False) -> dict[str, ProbeResult]:
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(concurrency)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=min(concurrency, 64))
    results: dict[str, ProbeResult] = {}

    async def task(c: dict):
        key = f"{c['ip']}|{c['port']}"
        async with sem:
            try:
                if sim:
                    res = simulate_probe(c, backends)
                else:
                    res = await loop.run_in_executor(
                        ex, probe_one_combo_sync, c["ip"], c["port"], backends, timeout, retries,
                        time.monotonic() + candidate_deadline, min_passes)
            except Exception as e:                       # ⛔ 不许让异常把候选变成「未测量却被当存活」
                res = ProbeResult(c["ip"], c["port"])
                res.error = f"probe:{type(e).__name__}"
        results[key] = res

    try:
        await asyncio.gather(*(task(c) for c in cands), return_exceptions=True)
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def simulate_probe(c: dict, backends: list[dict]) -> ProbeResult:
    """--dry-run 用的确定性伪探活：完全不联网，只造出「有死有活、端口非标有差异」的分布，
    用来验配额/去重/短路逻辑。规则固定可复现：
      · 末位八位组能被 7 整除的 IP ⇒ TCP 直接死（约 1/7 样本）
      · 非标端口(2053/2083/2096/8443) ⇒ 只允许一半后端通过，逼出「X 变体省略」路径
      · 其余按 sha256(ip:port) 的位决定各后端通过与否
    """
    res = ProbeResult(c["ip"], c["port"])
    tail = int(c["ip"].split(".")[-1])
    if tail % 7 == 0:
        res.error = "sim:tcp:fail"
        return res
    res.tcp_ok = True
    h = int(hashlib.sha256(f"{c['ip']}:{c['port']}".encode()).hexdigest(), 16)
    allow = len(backends) // 2 if c["port"] in NON_STANDARD_PORTS else len(backends)
    for idx in range(max(1, allow)):
        bit = (h >> idx) & 1
        if bit or idx == 0:
            res.passes.append(idx % max(1, len(backends)))
            res.detail[str(idx)] = "101"
        else:
            res.detail[str(idx)] = "ws:403"
        if len(res.passes) >= PROBE_MIN_PASSES:
            for rest in range(idx + 1, max(1, allow)):
                res.detail[str(rest)] = "skipped:short-circuit"
            break
    return res


def probe_all(cands: list[dict], backends: list[dict], args, sim: bool) -> tuple[dict, dict]:
    jobs = [{"ip": c["ip"], "port": c["port"], "source": c.get("source")} for c in
            {f"{c['ip']}|{c['port']}": c for c in cands}.values()]
    # 安全阀：Actions 出口是数据中心 IP，对海量随机 IP 做 TCP+TLS+WS 有触发滥用检测的风险，
    # 且 40min workflow 超时会留下半跑状态。超出上限的候选按「未测量」拒收（fail-closed），
    # 不影响已填够的家族。默认 3000，够 150 节点池用（现网候选量级 ~1500）。
    if args.probe_limit and len(jobs) > args.probe_limit:
        log(f"⚠ 候选 (ip,port) 共 {len(jobs)} 条 > 探活上限 {args.probe_limit} ⇒ 截断，"
            f"其余 {len(jobs) - args.probe_limit} 条按未测量拒收")
        stats_cut = len(jobs) - args.probe_limit
        # 按源轮转抽样：直接切前 N 条会让排在后面的源（gslege/hostmonit 等）整源饿死
        _buckets: dict[str, list[dict]] = {}
        for _j in jobs:
            _buckets.setdefault(str(_j.get("source") or "?"), []).append(_j)
        _sampled: list[dict] = []
        while len(_sampled) < args.probe_limit and any(_buckets.values()):
            for _k in list(_buckets):
                if not _buckets[_k]:
                    continue
                _sampled.append(_buckets[_k].pop(0))
                if len(_sampled) >= args.probe_limit:
                    break
        jobs = _sampled
        stats_cut = 0
    else:
        stats_cut = 0
    log(f"探活开始: {len(jobs)} 个 (ip,port) × {len(backends)} 条 ws 后端，"
        f"并发 {args.workers}，超时 {args.timeout}s，重试 {args.retries} 次")
    t0 = time.monotonic()
    results = asyncio.run(_probe_async(
        jobs, backends, args.timeout, args.retries, args.workers,
        args.candidate_deadline, args.min_passes, sim=sim))
    alive = {k: r for k, r in results.items() if r.passes}
    ratio = (len(alive) / len(jobs)) if jobs else 0.0
    code_counts: dict[str, int] = {}
    for r in results.values():
        tag = r.error or (r.detail.get("0") if not r.passes else "alive")
        code_counts[str(tag).split(":")[0]] = code_counts.get(str(tag).split(":")[0], 0) + 1
    summary = {
        "target_pairs": len(jobs), "tcp_alive": sum(1 for r in results.values() if r.tcp_ok),
        "alive_pairs": len(alive), "alive_ratio": round(ratio, 4),
        "missing_results": len(jobs) - len(results),
        "probe_truncated": stats_cut,
        "fail_kinds": code_counts, "seconds": round(time.monotonic() - t0, 1),
        "simulated": bool(sim),
    }
    log(f"探活完成: {len(alive)}/{len(jobs)} 存活（{ratio:.1%}），用时 {summary['seconds']}s")
    return results, summary


def run_positive_control(ws_backends: list[dict], timeout: float, retries: int
                         ) -> list[tuple[str, bool, str]]:
    """正对照（判据来自台账 L2 第⑤条：测量通道本身坏了 ⇒ 整批结论作废，不许出报告）。

    对照组就用 base 里**真实的 ws 后端**：以它自己的 server 作 IP/域名、自己的 SNI+Host+path
    走完整三层。这些后端是订阅里正在用的活口子，若**全部**连不上 101，说明是本机/runner 出口
    或探测代码坏了，而不是优选池死了 —— 此时后续算出来的任何存活率都是假账。
    """
    def one(i_be: tuple[int, dict]) -> tuple[str, bool, str]:
        i, be = i_be
        # ⛔ 日志与 artifact 都在公开仓可见 ⇒ 只报序号，不报后端域名/节点名
        name = f"backend#{i}"
        host = be.get("server") or ""
        port = int(be.get("port") or 443)
        if not host:
            return name, False, "no-server"
        r = probe_one_combo_sync(host, port, [be], timeout, int(retries),
                                 time.monotonic() + timeout * 4, 1)
        tag = "101" if r.passes else (r.error or r.detail.get("0") or "fail")
        return name, bool(r.passes), str(tag)

    jobs = list(enumerate(ws_backends))
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, len(jobs)))) as ex:
        return list(ex.map(one, jobs))


# =====================================================================
# 7) 家族配额（bug #1/#2/#4 全在这一层）
# =====================================================================

def family_cap(fam: str) -> int:
    """bug #4 口径：FAMILY_TARGET 记**最终节点数**，填充闸门按节点数算（见 family_nodes/_fam_full）。
    这里只留一个**防跑飞的硬 IP 上限**：最坏情形每个 IP 只活 1 条后端 ⇒ 1 节点，故 IP 数不得超过 target。
    """
    target = FAMILY_TARGET.get(fam)
    return 0 if target is None else target          # bug #1：白名单外家族 = 0，直接拒收


def family_nodes(families: dict, fam: str) -> int:
    """该家族已占用的**节点数**（不是 IP 数）—— 配额按这个口径填，才不会被 X 变体跳过拖成欠配。"""
    return sum(x.get("nodes", 1) for x in families.get(fam, []))


def _fam_full(families: dict, fam: str) -> bool:
    if fam not in FAMILY_TARGET:
        return True                                  # bug #1 双保险
    return (family_nodes(families, fam) >= FAMILY_TARGET[fam]
            or len(families.get(fam, [])) >= family_cap(fam))


def pick_family(fams: list[str], families: dict, rr: dict) -> str | None:
    """bug #2：跨家族共享候选池、各家族各自填到**节点目标**为止。

    v10 用 `add(fams[i % len])`，i 每来一个候选就 +1，先满员的家族其轮次整条丢弃、
    不顺延给同地区另一家 ⇒ 配额吃不满且随上游顺序漂移（现网 港岛茶记18 / 香港20 非对称）。
    这里保留轮转起点（维持并存家族同时进人），但满员时**顺延**到下一个未满家族。
    """
    if len(fams) == 1:
        fam = fams[0]
        return None if _fam_full(families, fam) else fam
    start = rr.get(tuple(fams), 0) % len(fams)
    rr[tuple(fams)] = start + 1
    for off in range(len(fams)):
        fam = fams[(start + off) % len(fams)]
        if not _fam_full(families, fam):
            return fam
    return None


class _AdvisoryPass:
    """探活降级用的占位结果：探活失败但仍要入池的候选，借用已知活后端的下标。"""
    __slots__ = ("passes",)
    def __init__(self, passes: list[int]):
        self.passes = list(passes)


def assign_families(cands: list[dict], probe_results: dict, only_us: bool,
                    stats: dict, advisory: bool = False,
                    fallback_backends: list[int] | None = None) -> dict[str, list[dict]]:
    families: dict[str, list[dict]] = {}
    rr: dict[tuple, int] = {}
    dropped_whitelist = dropped_dead = dropped_cap = dropped_unmeasured = 0
    advisory_added = 0
    fallback = list(fallback_backends or [])
    _is_advisory = False

    if advisory and fallback:
        # 探活降级：存活候选排前面（0），探活失败的后排（1），未测量的最后（2）。
        # ⛔ 只降优先级、不判死 —— runner 出口≠用户出口，境外探活失败是假阴性。
        def _rank(it: dict) -> int:
            pr = probe_results.get(f"{it['ip']}|{it['port']}")
            if pr is None:
                return 2
            return 0 if pr.passes else 1
        cands = sorted(cands, key=_rank)

    for it in cands:
        fams: list[str] | None = None
        if it.get("brand") and it["brand"] in BRAND_FAMILIES:
            fams = [it["brand"]]
        elif it.get("region") and it["region"] in REGION_FAMILIES:
            fams = REGION_FAMILIES[it["region"]]
        elif not it.get("region") and it.get("isp") and it["isp"] in ISP_FAMILIES:
            fams = [ISP_FAMILIES[it["isp"]]]

        if only_us:
            # bug #1 拆雷：ONLY_US 分支只作地区过滤，落到的家族名恒为标准名「美国」，
            # 不再用 v10 写死的「战争贩子」（不在 FAMILY_TARGET ⇒ 曾经回退 120 IP 打爆配额）。
            std = it.get("region")
            if std not in (None, "美国"):
                continue
            fams = [ONLY_US_FALLBACK_FAMILY]

        if not fams:
            dropped_whitelist += 1
            continue
        fams = [f for f in fams if f in FAMILY_TARGET]        # 双保险：标准名之外一律不进
        if not fams:
            dropped_whitelist += 1
            continue

        pr = probe_results.get(f"{it['ip']}|{it['port']}")
        # ⛔ fail-closed：没测到结果的候选一律不许进池（v10 那种「没探也算活」会把未验证节点推上线）。
        # passes 为空 = 三层没拿到 101 ⇒ 判死；pr 为 None = 该 (ip,port) 根本没被测量 ⇒ 同样不收，单独计数。
        if pr is None:
            dropped_unmeasured += 1
            continue
        if not pr.passes:
            if not (advisory and fallback):
                dropped_dead += 1
                continue
            # 探活降级：只放行「TCP 通了但后续层失败」的候选 —— TCP 都连不上是客观死，
            # 数据中心出口都不通，用户侧只会更差，不许降级。
            if not getattr(pr, "tcp_ok", False):
                dropped_dead += 1
                continue
            # 只借一条后端：未验证的 IP 不许产出 X 变体（第二条后端纯属轮转臆测）
            pr = _AdvisoryPass(fallback[:1])
            _is_advisory = True

        fam = pick_family(fams, families, rr)
        if fam is None:
            dropped_cap += 1
            continue
        if any(x["ip"] == it["ip"] and x["port"] == it["port"] for x in families.setdefault(fam, [])):
            continue                                          # 家族内 IP+端口 去重（同 v10）

        passes = list(pr.passes)
        nodes = min(2, len(passes))                             # 主节点 + X 变体
        remaining = FAMILY_TARGET[fam] - family_nodes(families, fam)
        if nodes > remaining:                                   # 只补到目标为止，不许超配
            passes = passes[:max(1, remaining)]
            nodes = len(passes)
        families[fam].append({"ip": it["ip"], "port": int(it["port"]),
                              "passes": passes, "nodes": nodes,
                              "advisory": bool(_is_advisory),
                              "source": it.get("source")})
        if _is_advisory:
            advisory_added += 1
        _is_advisory = False

    families = {k: v for k, v in families.items() if v}
    stats["quota"] = {
        "whitelisted_families": len(families),
        "dropped_not_whitelisted": dropped_whitelist,
        "dropped_probe_dead": dropped_dead,
        "dropped_unmeasured": dropped_unmeasured,
        "dropped_all_families_full": dropped_cap,
        "probe_advisory": bool(advisory),
        "advisory_added": advisory_added,
        "per_family_slots": {k: len(v) for k, v in families.items()},
        "per_family_target_nodes": {k: FAMILY_TARGET[k] for k in families},
        "per_family_nodes": {k: family_nodes(families, k) for k in families},
        "per_family_hard_ip_cap": {k: family_cap(k) for k in families},
    }
    log("家族配额:", " ".join(f"{k}:{family_nodes(families, k)}/{FAMILY_TARGET[k]}节点"
                             for k in families),
        f"（非白名单丢弃 {dropped_whitelist}、探活判死 {dropped_dead}、未测拒收 {dropped_unmeasured}、"
        f"池满丢弃 {dropped_cap}）")
    return families


# =====================================================================
# 8) 配置合成（沿用 v10 buildConfig 全部行为）
# =====================================================================

def fix_reality_opts(backends: list[dict]) -> int:
    """驼峰 publicKey → 连字符 public-key（mihomo 只认后者；2026-09-28 事故防御，照搬 v10）。"""
    fixed = 0
    for p in backends:
        ro = p.get("reality-opts")
        if isinstance(ro, dict) and "publicKey" in ro:
            ro["public-key"] = ro.pop("publicKey")
            fixed += 1
    return fixed


def pick_backend(passes: list[int] | None, n: int, start: int, exclude: int | None) -> int | None:
    """从「实测通过的后端下标」里按 v10 轮转起点顺延取一个；passes=None 表示未探活（全允许）。"""
    if n <= 0:
        return None
    allowed = set(range(n)) if passes is None else {i for i in passes if 0 <= i < n}
    if not allowed:
        return None
    for off in range(n):
        k = (start + off) % n
        if k in allowed and (exclude is None or k != exclude):
            return k
    return None


def build_config(base: dict, families: dict[str, list[dict]], stats: dict,
                 drop_backends: set[str] = frozenset(),
                 extra_nodes: list[dict] | None = None) -> str:
    # drop_backends：正对照已证明连不上的 ws 后端。它们留在产物里只是给用户多几个「点了没反应」的坑，
    # ⛔ 没有实测证据的后端（非 ws 模板那几条）不在此列，一律原样保留。
    all_backends = list(base.get("proxies") or [])
    backends = [p for p in all_backends if p.get("name") not in drop_backends]
    stats["dropped_dead_backends"] = len(all_backends) - len(backends)
    stats["reality_fixed"] = fix_reality_opts(backends)
    # 克隆模板表必须用**未过滤**的全量列表：探活时 passes 记的是这张表里的下标，
    # 一旦在这里删条目就会让下标错位（n 变小 ⇒ pick_backend 取不到 allowed ⇒ 整池归零）。
    ws_backends = [p for p in all_backends
                   if p.get("network") == "ws" and p.get("template") is not False]
    n = len(ws_backends)
    # 已判死后端在 ws_backends 里的下标。pick_backend 只保证下标在范围内，
    # 不保证不在 drop 集 ⇒ 这里显式过滤，避免克隆出指向死域名的节点。
    _dead_idx = {i for i, p in enumerate(ws_backends) if p.get("name") in drop_backends}
    proxies: list[dict] = []
    skipped_x = 0
    nodes_per_family: dict[str, int] = {}
    for fam, slots in families.items():
        suffix = f" ({REGION_OF_FUN[fam]})" if fam in REGION_OF_FUN else ""
        made = 0
        for idx, slot in enumerate(slots):
            if n == 0:
                break
            _p = slot.get("passes")
            if _p is None:
                _allowed = None
            else:
                _allowed = [i for i in _p if i not in _dead_idx]
                if not _allowed:
                    continue          # 该槽位只指向已判死后端 ⇒ 不出节点
            main = pick_backend(_allowed, n, idx % n, None)
            if main is None:
                continue
            q = json.loads(json.dumps(ws_backends[main], ensure_ascii=False))
            q["name"] = f"{fam}-{idx + 1:02d}{suffix}"
            q["server"] = slot["ip"]
            q["port"] = int(slot.get("port") or 443)
            # 优先用模板自己的 servername（SNI≠server 的后端如 CF for SaaS 不能被覆盖）
            _sni = ws_backends[main].get("servername") or ws_backends[main].get("server")
            q["servername"] = _sni
            if isinstance(q.get("ws-opts"), dict) and isinstance(q["ws-opts"].get("headers"), dict):
                q["ws-opts"]["headers"]["Host"] = _sni
            proxies.append(q)
            made += 1
            # X 变体：同 IP 同端口、换挂另一条后端域名（v10 口径；只探到 1 条通过时不硬凑）
            second = pick_backend(_allowed, n, (idx + 1) % n, main)
            if second is None:
                skipped_x += 1
                continue
            x = json.loads(json.dumps(ws_backends[second], ensure_ascii=False))
            x["name"] = f"{fam}-{idx + 1:02d}X{suffix}"
            x["server"] = slot["ip"]
            x["port"] = int(slot.get("port") or 443)
            _sni2 = ws_backends[second].get("servername") or ws_backends[second].get("server")
            x["servername"] = _sni2
            if isinstance(x.get("ws-opts"), dict) and isinstance(x["ws-opts"].get("headers"), dict):
                x["ws-opts"]["headers"]["Host"] = _sni2
            proxies.append(x)
            made += 1
        nodes_per_family[fam] = nodes_per_family.get(fam, 0) + made
    stats["nodes_preferred"] = len(proxies)
    stats["nodes_per_family"] = nodes_per_family
    stats["skipped_x_variants"] = skipped_x
    stats["ws_template_backends"] = n

    all_names = [p["name"] for p in proxies]
    backend_names = [p["name"] for p in backends]
    base_groups = json.loads(json.dumps(base.get("proxy-groups") or [], ensure_ascii=False))
    auto_group = {"name": "♻️ 优选自动", "type": "url-test",
                  "url": "http://www.gstatic.com/generate_204", "interval": 300,
                  "tolerance": 50, "proxies": [*all_names, *backend_names]}
    base_groups.append(auto_group)
    # 组员清洗：组里引用不存在的节点会让 mihomo 直接拒载整份订阅
    valid_refs = set(backend_names) | set(all_names) | {g.get("name") for g in base_groups} \
        | {"DIRECT", "REJECT"}
    for g in base_groups:
        if not isinstance(g.get("proxies"), list):
            continue
        g["proxies"] = [x for x in g["proxies"] if x in valid_refs]
        if not g["proxies"]:
            g["proxies"] = ["DIRECT"]
    main = next((g for g in base_groups if g.get("name") == "🔰 选择节点"),
                base_groups[0] if base_groups else None)
    if main and isinstance(main.get("proxies"), list):
        rest = [x for x in main["proxies"] if x not in ("DIRECT", auto_group["name"])]
        merged = [auto_group["name"], *rest, *backend_names, *all_names, "DIRECT"]
        seen, uniq = set(), []
        for x in merged:
            if x not in seen:
                seen.add(x)
                uniq.append(x)
        main["proxies"] = uniq
    cfg = dict(base)
    cfg["proxies"] = [*backends, *proxies]
    cfg["proxy-groups"] = base_groups
    # 自建 VPS 节点（2026-10-28）：内容只从 secret EXTRA_NODES 读，⛔ 仓库里零凭据。
    # 不注入时整段是 no-op，产物与改动前逐字节一致。
    extra = [p for p in (extra_nodes or []) if isinstance(p, dict) and p.get("name")]
    if extra:
        extra_names = [p["name"] for p in extra]
        cfg["proxies"] = [p for p in cfg["proxies"] if p.get("name") not in extra_names] + extra
        own_name = "🖥 自有VPS"
        own_proxies = [*extra_names, auto_group["name"], "DIRECT"]
        existing = next((g for g in base_groups if g.get("name") == own_name), None)
        if existing is not None:
            existing["type"] = "select"
            existing["proxies"] = own_proxies
        else:
            base_groups.append({"name": own_name, "type": "select", "proxies": own_proxies})
        if main and isinstance(main.get("proxies"), list):
            main["proxies"] = [own_name] + [x for x in main["proxies"] if x != own_name]
        if main:
            # 默认落到自建节点组：与 Mac 侧 Clash Verge 扩展脚本的口径一致，
            # 新装/新导入的客户端拉下来即用自有节点，不用手动点。
            main["now"] = own_name
        stats["extra_nodes"] = len(extra)
    stats["proxies_total"] = len(cfg["proxies"])
    # json.dumps 必须 ensure_ascii=False：JS 的 JSON.stringify 直出 UTF-8 汉字，
    # 默认 True 会把中文转义成 \uXXXX，体积与观感都变（L1 落盘验约束）。
    return json.dumps(cfg, indent=1, ensure_ascii=False)


EXTRA_NODES_ENV = "EXTRA_NODES"   # secret：自建 VPS 节点 JSON 数组；⛔ 值绝不进仓库、日志、artifact


def load_extra_nodes() -> list[dict]:
    """自 secret 读自建 VPS 节点。未配置 / 格式不对 ⇒ 返回空列表，主流程照旧。

    只做形状校验，不做任何网络动作；uuid 一进来就登记进脱敏表，
    保证后续 log()/异常文本里不会出现节点凭据。
    """
    raw = (os.environ.get(EXTRA_NODES_ENV) or "").strip()
    if not raw:
        return []
    try:
        arr = json.loads(raw)
    except Exception as e:
        log("自建节点 JSON 解析失败（按无自建节点继续）:", redact(e))
        return []
    if not isinstance(arr, list):
        log("自建节点格式不是数组（按无自建节点继续）")
        return []
    keep: list[dict] = []
    for item in arr:
        if not isinstance(item, dict):
            continue
        if not (item.get("name") and item.get("server") and item.get("uuid")):
            continue
        register_secret(str(item.get("uuid")))
        register_secret(str(item.get("server")))
        keep.append(item)
    return keep


# =====================================================================
# 9) Cloudflare KV —— 原始 REST API（⛔ 不用 wrangler；id 一律取当次响应）
# =====================================================================

class CFKV:
    def __init__(self, token: str, account_id_hint: str | None, ns_title: str, timeout: float = 30.0):
        if not token:
            raise FetchError("缺少 CF_API_TOKEN")
        self.token = token
        self.hint = account_id_hint
        self.ns_title = ns_title
        self.timeout = timeout
        self.account_id: str | None = None
        self.ns_id: str | None = None

    def _req(self, method: str, path: str, body: bytes | None = None,
             content_type: str = "application/json") -> bytes:
        url = f"{CF_API_BASE}{path}"
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json",
                   "User-Agent": UA}
        if body is not None:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                payload = json.loads(e.read().decode("utf-8", errors="replace"))
                errs = payload.get("errors") or []
                detail = " ".join(str(x.get("code")) for x in errs if isinstance(x, dict))
            except Exception:
                pass
            raise FetchError(f"CF API {method} {_mask_path(path)} → HTTP {e.code} {detail}".strip()) from None
        except Exception as e:
            raise FetchError(f"CF API {method} {_mask_path(path)} → {type(e).__name__}") from None

    def resolve(self) -> tuple[str, str]:
        """account id / namespace id 都从**当次**响应取，绝不写死字面值。"""
        if self.account_id is None:
            data = json.loads(self._req("GET", "/accounts").decode())
            accs = [a.get("id") for a in (data.get("result") or []) if a.get("id")]
            if not accs:
                raise FetchError("token 看不到任何 account")
            if self.hint:
                if self.hint not in accs:
                    raise FetchError(f"CF_ACCOUNT_ID 不在本次 /accounts 响应的 {len(accs)} 个账号内")
                self.account_id = self.hint
            elif len(accs) == 1:
                self.account_id = accs[0]
            else:
                raise FetchError(f"/accounts 返回 {len(accs)} 个账号，需显式给 CF_ACCOUNT_ID")
        if self.ns_id is None:
            q = urllib.parse.urlencode({"per_page": "100"})
            data = json.loads(self._req(
                "GET", f"/accounts/{self.account_id}/storage/kv/namespaces?{q}").decode())
            match = [x.get("id") for x in (data.get("result") or [])
                     if x.get("title") == self.ns_title and x.get("id")]
            if not match:
                raise FetchError(f"命名空间 title={self.ns_title!r} 不存在")
            self.ns_id = match[0]
        return self.account_id, self.ns_id

    def get_value(self, key: str) -> str | None:
        self.resolve()
        path = f"/accounts/{self.account_id}/storage/kv/namespaces/{self.ns_id}/values/" \
               f"{urllib.parse.quote(key, safe='')}"
        try:
            return self._req("GET", path).decode("utf-8", errors="replace")
        except FetchError as e:
            if "HTTP 10044" in str(e) or "HTTP 404" in str(e):
                return None
            raise

    def put_value(self, key: str, value: str) -> None:
        self.resolve()
        path = f"/accounts/{self.account_id}/storage/kv/namespaces/{self.ns_id}/values/" \
               f"{urllib.parse.quote(key, safe='')}"
        self._req("PUT", path, value.encode("utf-8"), content_type="text/plain;charset=utf-8")

    def list_keys(self, prefix: str) -> list[str]:
        self.resolve()
        keys: list[str] = []
        cursor = None
        while True:
            params = {"prefix": prefix, "limit": "1000"}
            if cursor:
                params["cursor"] = cursor
            data = json.loads(self._req(
                "GET", f"/accounts/{self.account_id}/storage/kv/namespaces/{self.ns_id}/keys?"
                       f"{urllib.parse.urlencode(params)}").decode())
            res = data.get("result") or []
            keys += [k.get("name") for k in res if isinstance(k, dict) and k.get("name")]
            cursor = (data.get("result_info") or {}).get("cursor") or None
            if not cursor or not res:
                break
        return keys


def kv_value_shape(yaml_text: str, userinfo: str) -> str:
    """形状写死：{"yaml": "<配置JSON文本>", "userinfo": "<空格分隔原样串>"} —— 写错 Worker 404。"""
    return json.dumps({"yaml": yaml_text, "userinfo": userinfo}, ensure_ascii=False)


def read_userinfo(kv: CFKV | None, real_key: str, shadow_key: str, fallback: str) -> str:
    """原样透传 userinfo（⛔ 不改分号分隔）；只读不回显内容。"""
    for key in (shadow_key, real_key):
        raw = None
        try:
            raw = kv.get_value(key) if kv else None
        except Exception:
            raw = None
        if raw:
            try:
                obj = json.loads(raw)
                if isinstance(obj, dict) and isinstance(obj.get("userinfo"), str) and obj["userinfo"]:
                    return obj["userinfo"]
            except Exception:
                pass
    return fallback or ""


def count_proxies(yaml_text: str | None) -> int | None:
    if not yaml_text:
        return None
    try:
        obj = json.loads(yaml_text)
    except Exception:
        return None
    p = obj.get("proxies")
    return len(p) if isinstance(p, list) else None


# =====================================================================
# 10) 主流程
# =====================================================================

SAMPLE_BASE = {
    "mixed-port": 7890, "mode": "rule", "log-level": "info",
    "proxies": [
        {"name": "BE-ALPHA", "type": "vless", "server": "alpha.example.com", "port": 443,
         "uuid": "SAMPLE-UUID-0", "udp": True, "tls": True, "servername": "alpha.example.com",
         "network": "ws", "ws-opts": {"path": "/ws", "headers": {"Host": "alpha.example.com"}}},
        {"name": "BE-BETA", "type": "vless", "server": "beta.example.com", "port": 443,
         "uuid": "SAMPLE-UUID-1", "udp": True, "tls": True, "servername": "beta.example.com",
         "network": "ws", "ws-opts": {"path": "/vless-ws", "headers": {"Host": "beta.example.com"}}},
        {"name": "BE-GAMMA", "type": "vless", "server": "gamma.example.com", "port": 443,
         "uuid": "SAMPLE-UUID-2", "udp": True, "tls": True, "servername": "gamma.example.com",
         "network": "ws", "ws-opts": {"path": "/ws", "headers": {"Host": "gamma.example.com"}}},
        {"name": "BE-NOCLONE", "type": "vless", "server": "noclone.example.com", "port": 443,
         "uuid": "SAMPLE-UUID-3", "network": "ws", "template": False,
         "reality-opts": {"publicKey": "DIRTY_CAMEL_KEY", "short-id": ""},
         "ws-opts": {"path": "/x", "headers": {"Host": "noclone.example.com"}}},
    ],
    "proxy-groups": [
        {"name": "🔰 选择节点", "type": "select",
         "proxies": ["♻️ 优选自动", "BE-ALPHA", "GHOST-NODE-不存在", "DIRECT"]},
        {"name": "🐟 漏网之鱼", "type": "select", "proxies": ["🔰 选择节点", "REJECT"]},
    ],
    "rules": ["MATCH,🐟 漏网之鱼"],
}


def sample_candidates() -> list[dict]:
    """--dry-run 输入：模拟上游各路（含多端口 IP、重复行、白名单外家族、非美国地区）
    —— 专门用来验 bug #3(端口入键)、#2(满员顺延)、#1(非白名单名一律拒收)、#5(非标端口)。"""
    out: list[dict] = []
    fam_plan = [(k, v) for k, v in FAMILY_TARGET.items()]
    ip_n = 0

    def mk_ip() -> str:
        nonlocal ip_n
        ip_n += 1
        return f"198.18.{ip_n // 250}.{ip_n % 250 or 1}"

    for fam, target in fam_plan:
        region = None if fam in BRAND_FAMILIES else REGION_OF_FUN.get(fam)
        brand = fam if fam in BRAND_FAMILIES else None
        # 移动/电信 靠 isp 归族（v10 口径：region 为空 + isp 命中才进 ISP 家族）
        isp = fam if (fam in ISP_FAMILIES and brand is None and region is None) else None
        for _ in range(target * 2 + 8):        # 大幅超发：验「填到节点目标就停」和池满顺延
            ip = mk_ip()
            port = 443 if _ % 3 else 2096         # 一半走非标端口，验 bug #5
            out.append({"ip": ip, "port": port, "region": region, "isp": isp,
                        "brand": brand, "source": f"sample:{fam}"})
            out.append({"ip": ip, "port": port, "region": region, "isp": isp,
                        "brand": brand, "source": f"sample:{fam}"})   # 完全重复行 ⇒ 必须被去重
            if _ % 4 == 0:
                out.append({"ip": ip, "port": 8443, "region": region, "isp": isp,
                            "brand": brand, "source": f"sample:{fam}"})  # 同 IP 不同端口 ⇒ bug #3 回归点
    # 白名单外地雷：花名「战争贩子」/「元首复活」/「港岛茶记X」 一律不许成族
    for bad in ("战争贩子", "元首复活", "印加坡县"):
        out.append({"ip": mk_ip(), "port": 443, "region": None, "isp": None,
                    "brand": bad, "source": f"sample:{bad}"})
        out.append({"ip": mk_ip(), "port": 443, "region": bad, "isp": None,
                    "brand": None, "source": f"sample:{bad}"})
    out.append({"ip": "999.1.1.1", "port": 443, "region": "日本", "isp": None,
                "brand": None, "source": "sample:bad-ip"})
    return out


def load_base(kv: CFKV | None, path: str | None, dry: bool) -> dict:
    if path:
        with open(path, "r", encoding="utf-8") as f:
            return json.loads(f.read())
    if dry:
        return json.loads(json.dumps(SAMPLE_BASE))
    if kv is None:
        raise FetchError("既没给 --base-from 也没配 KV 凭据，无从读取 base:config")
    raw = kv.get_value("base:config")
    if not raw:
        raise FetchError("KV 里读不到 base:config")
    return json.loads(raw)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="sub-pool-builder: 抓取+三层探活+合成+写 KV")
    ap.add_argument("--dry-run", action="store_true",
                    help="完全不联网：用内置样本候选与伪探活，只验配额/去重/合成")
    ap.add_argument("--kv-prefix", default="test:",
                    help="写入 key 前缀，默认影子 key 'test:'；S6 验收前不得改成 ''")
    ap.add_argument("--promote", action="store_true",
                    help="额外写真实 key sub:<token>（仅在 S6 验收通过后使用）")
    ap.add_argument("--tokens", default="",
                    help="逗号分隔的订阅 token；留空则从 KV 的 sub: 前缀列出现有 token")
    ap.add_argument("--base-from", default=None, help="本地 base JSON 路径（跳过 KV 读 base）")
    ap.add_argument("--out", default=None, help="把合成结果写到本地文件（便于人工/验收 diff）")
    ap.add_argument("--only-us", default=os.environ.get("ONLY_US", "false"),
                    help="true=只收美国地区候选（家族名仍用标准名，见 bug #1）")
    ap.add_argument("--workers", type=int, default=PROBE_CONCURRENCY, help="探活并发上限")
    ap.add_argument("--timeout", type=float, default=PROBE_TIMEOUT, help="单层超时(秒)")
    ap.add_argument("--retries", type=int, default=PROBE_RETRIES, help="单 IP 重试次数")
    ap.add_argument("--min-passes", type=int, default=PROBE_MIN_PASSES,
                    help="单候选探到几条后端即短路（默认 2：主 + X 变体）")
    ap.add_argument("--candidate-deadline", type=float, default=PROBE_CANDIDATE_DEADLINE)
    ap.add_argument("--probe-limit", type=int, default=3000,
                    help="最多探测多少个 (ip,port)，超出按未测量拒收（0=不限）；防 Actions 出口被打进滥用名单")
    ap.add_argument("--min-alive-ratio", type=float, default=ALIVE_MIN_RATIO,
                    help="聚合存活率低于此值 ⇒ 判源面故障，不写 KV，退出码 2")
    ap.add_argument("--probe-advisory", dest="probe_advisory",
                    action=argparse.BooleanOptionalAction,
                    default=(os.environ.get("PROBE_ADVISORY", "true").lower() != "false"),
                    help="探活降级为参考（默认开）：探活失败的候选不判死，按存活优先排序后仍可入池")
    ap.add_argument("--no-probe", action="store_true",
                    help="跳过探活（全部后端视为可用；仅调试配额用，⛔ 不许用于正式刷新）")
    ap.add_argument("--skip-kv-write", action="store_true", help="只跑流程不写 KV")
    ap.add_argument("--dead-domains", default=os.environ.get("DEAD_DOMAINS", ""),
                    help="逗号分隔的死域名清单，命中 base 则在 meta 里告警（S4 核对钩子）")
    args = ap.parse_args(argv)

    only_us = str(args.only_us).strip().lower() in ("1", "true", "yes", "on")
    cf_token = os.environ.get("CF_API_TOKEN", "")
    cfyes_key = os.environ.get("CFYES_KEY", "")
    register_secret(cf_token)
    register_secret(cfyes_key)
    register_secret(os.environ.get("SUB_USERINFO", ""))

    stats: dict = {"started_at": now_iso(), "mode": "dry-run" if args.dry_run else "live",
                   "only_us": only_us, "sources": {}, "kv_prefix": args.kv_prefix,
                   "promote": bool(args.promote), "profile_update_interval": PROFILE_UPDATE_INTERVAL}
    log(f"sub-pool-builder 启动 mode={stats['mode']} only_us={only_us} "
        f"kv_prefix={args.kv_prefix!r} promote={stats['promote']}")

    # 影子 key 优先（任务书 §8 双写防护）：前缀为空 = 直接写真 key，必须同时显式 --promote
    if args.kv_prefix and not args.kv_prefix.endswith(":"):
        log("⛔ --kv-prefix 必须以冒号结尾（如 'test:'），否则 key 形状会变成 sub:<token> 以外的东西")
        return 2
    if args.kv_prefix == "" and not args.promote:
        log("⛔ --kv-prefix '' 会写真 key sub:<token>；S6 验收前请加 --kv-prefix test: 或显式 --promote")
        return 2

    kv: CFKV | None = None
    if not args.dry_run and not args.skip_kv_write:
        # ⚠ GitHub 对「未配置的 var」传的是**空字符串**而不是缺键 ⇒ os.environ.get(k, default)
        # 会返回 ''，把默认值吃掉（2026-10-16 首次 Actions 实跑就是栽在这里：title='' 找不到命名空间）。
        ns_title = os.environ.get("KV_NAMESPACE_TITLE") or KV_NAMESPACE_TITLE
        try:
            kv = CFKV(cf_token, os.environ.get("CF_ACCOUNT_ID") or None, ns_title)
            log(f"KV 就绪：绑定名 {KV_BINDING_NAME}，命名空间 title={ns_title}"
                "（account/namespace id 将于首次调用从 API 响应中取得，不写死）")
        except Exception as e:
            log("致命:", redact(e))
            _dump_stats(stats, args)
            return 1

    try:
        base = load_base(kv, args.base_from, args.dry_run)
    except Exception as e:
        log("致命:", redact(e))
        _dump_stats(stats, args)
        return 1

    # base 死域名核对钩子（S4）：只统计出现次数，⛔ 不在本任务里改 base
    if args.dead_domains:
        dead = [d.strip() for d in args.dead_domains.split(",") if d.strip()]
        text = json.dumps(base, ensure_ascii=False)
        # ⛔ artifact 上传到公开仓库 ⇒ 只记命中条数，绝不回显域名本身
        _hit_cnt = sum(1 for d in dead if d in text)
        stats["base_dead_domain_hits"] = _hit_cnt
        if _hit_cnt:
            log(f"⚠ base 仍含待清理域名（本任务不改）: 命中 {_hit_cnt}/{len(dead)} 条（域名不回显）")

    backends = base.get("proxies") or []
    ws_backends = [p for p in backends if p.get("network") == "ws" and p.get("template") is not False]
    stats["base_backends"] = len(backends)
    stats["ws_template_backends"] = len(ws_backends)
    log(f"base 后端 {len(backends)} 条，可克隆 ws 模板 {len(ws_backends)} 条")
    if not ws_backends:
        log("没有可克隆的 ws 后端，无法生成优选池")
        _dump_stats(stats, args)
        return 1

    if args.dry_run:
        cands = dedup_candidates(sample_candidates())
        stats["sources"]["dry-run-sample"] = {"ok": True, "count": len(cands), "errors": 0}
    else:
        cands = dedup_candidates(collect_candidates(only_us, cfyes_key, stats))
    stats["candidates_deduped"] = len(cands)
    port_kinds = {}
    for c in cands:
        port_kinds[c["port"]] = port_kinds.get(c["port"], 0) + 1
    stats["candidate_ports"] = port_kinds
    log(f"去重后候选 {len(cands)} 条（键=ip|brand|port），端口分布:",
        " ".join(f"{p}:{n}" for p, n in sorted(port_kinds.items())))

    # 正对照闸门：先证明「探测通道本身是活的」，再让通道去判几千个候选的死活。
    # 对照组全灭 ⇒ 出口/代码故障，本次不产出任何存活结论（台账 L2 第⑤条的落地）。
    drop_backends: set[str] = set()
    if not args.dry_run and not args.no_probe:
        ctl = run_positive_control(ws_backends, args.timeout, args.retries)
        stats["positive_control"] = [{"backend": n, "alive": a, "why": w} for n, a, w in ctl]
        log("正对照(TCP+TLS+WS):", " ".join(f"{n}:{'活' if a else w}" for n, a, w in ctl))
        if not any(a for _, a, _ in ctl):
            log("⛔ 对照组全灭 ⇒ 测量通道坏了，本次候选存活率一律作废（不写 KV）")
            stats["abort_reason"] = "positive_control_all_dead"
            if kv is not None:
                _write_meta(kv, args, stats)
            return 5
        # 有实测证据说死的 ws 后端不再进产物（非 ws 的那几条没有证据，保留）。
        # ⛔ 只剔「客观已死」：530/1016＝源站已下线、gaierror＝域名根本不解析、no-server＝配置残缺。
        # TimeoutError 一类**不许剔** —— runner 出口不等于用户出口，地域性超时是假阴性，
        # 剔掉会把用户这边其实能用的口子从订阅里删掉（台账 L2 第⑤条的同形风险）。
        def _is_objective_dead(tag: str) -> bool:
            """只认「客观已下线」：源站 530/1016、域名不解析、配置残缺、协议层明确拒绝。
            ⛔ tls:* 一律不判死 —— runner 出口≠用户出口，地域性 TLS 抖动是假阴性。"""
            if tag == "no-server":
                return True
            kind, _, rest = tag.partition(":")
            if kind == "tcp" and rest.startswith("gaierror"):
                return True
            if kind == "ws" and rest.split(":")[0] in ("530", "1016", "400", "404"):
                return True
            return False
        drop_idx = {i for i, (_, a, w) in enumerate(ctl) if not a and _is_objective_dead(str(w))}
        drop_backends = {ws_backends[i]["name"] for i in drop_idx if ws_backends[i].get("name")}
        stats["positive_control_drop_idx"] = sorted(drop_idx)
        stats["positive_control_kept_uncertain"] = [i for i in range(len(ctl))
                                                    if not ctl[i][1] and i not in drop_idx]
        log("已判死并从产物里剔除的后端下标:", str(sorted(drop_idx)) or "无",
            "（超时类一律保留：%s）" % stats["positive_control_kept_uncertain"])

    if args.no_probe:
        # ⛔ 闸门：--no-probe 让所有候选拿到全部后端下标（含已判死的），且 alive_ratio=1.0 会骗过
        # 0.3 存活率闸门。必须限制在「不写 KV」的场合，否则一条命令就能把死后端推上生产。
        if not args.dry_run and not args.skip_kv_write:
            log("⛔ --no-probe 只允许配合 --dry-run 或 --skip-kv-write（拒绝写 KV）")
            return 2
        results = {f"{c['ip']}|{c['port']}": ProbeResult(c["ip"], c["port"]) for c in cands}
        for r in results.values():
            r.tcp_ok, r.passes = True, list(range(len(ws_backends)))
        probe_summary = {"target_pairs": len(results), "alive_pairs": len(results),
                         "alive_ratio": 1.0, "simulated": False, "note": "--no-probe"}
        log("⚠ 已跳过探活（--no-probe），本次结果不可用于正式刷新")
    else:
        results, probe_summary = probe_all(cands, ws_backends, args, sim=args.dry_run)
    stats["probe"] = probe_summary
    if probe_summary.get("missing_results"):
        log(f"⚠ {probe_summary['missing_results']} 个候选没拿到探测结果 ⇒ 按未测量拒收，不进池")

    if probe_summary["alive_pairs"] == 0:
        log("探活全军覆没 —— 无法区分是源面故障还是出口限流")
        if not args.dry_run:
            _write_meta(kv, args, stats)
            return 2
    ratio = probe_summary.get("alive_ratio", 0.0)
    if ratio < args.min_alive_ratio:
        log(f"存活率 {ratio:.1%} < 阈值 {args.min_alive_ratio:.0%} ⇒ 判源面故障：不写 KV")
        stats["abort_reason"] = "alive_ratio_below_threshold"
        if not args.dry_run:
            _write_meta(kv, args, stats)
        return 2

    # 探活降级：兜底后端 = 正对照判活的；若没有正对照（--no-probe）则用全部未剔除的
    advisory_on = bool(getattr(args, "probe_advisory", False))
    fallback_backends: list[int] = []
    if advisory_on:
        ctl = stats.get("positive_control") or []
        if ctl:
            fallback_backends = [i for i, c in enumerate(ctl) if c.get("alive")]
            if not fallback_backends:
                _drop = set(stats.get("positive_control_drop_idx") or [])
                fallback_backends = [i for i in range(len(ws_backends)) if i not in _drop]
        else:
            fallback_backends = list(range(len(ws_backends)))
        log(f"探活降级为参考: 兜底后端下标 {fallback_backends}（探活失败不再判死）")

    families = assign_families(cands, results, only_us, stats,
                               advisory=advisory_on,
                               fallback_backends=fallback_backends)
    if not families:
        log("优选池为空 —— 保留旧配置，不写 KV")
        stats["abort_reason"] = "empty_pool"
        if not args.dry_run:
            _write_meta(kv, args, stats)
        return 2

    yaml_text = build_config(base, families, stats, drop_backends, load_extra_nodes())
    new_count = count_proxies(yaml_text) or 0
    stats["yaml_bytes"] = len(yaml_text.encode("utf-8"))
    stats["yaml_sha256"] = sha256_of(yaml_text)
    log(f"合成完成: {stats['proxies_total']} 个 proxy（优选 {stats['nodes_preferred']}，"
        f"X 变体缺第二条后端跳过 {stats['skipped_x_variants']}），"
        f"{stats['yaml_bytes'] / 1024:.0f}KB sha={stats['yaml_sha256'][:12]}")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(yaml_text)
        log("已写出:", args.out)

    # ---- tokens ----
    tokens = [t.strip() for t in args.tokens.split(",") if t.strip()]
    if not tokens and not args.dry_run and kv is not None:
        try:
            tokens = sorted(k.split(":", 1)[1] for k in kv.list_keys("sub:")
                            if k.startswith("sub:") and ":" in k)
        except Exception as e:
            log("列 sub: 前缀失败:", redact(e))
    if not tokens:
        tokens = ["0000000000000000"] if args.dry_run else []
    for _t in tokens:
        register_secret(_t)          # 双保险：redact 对 urlencoded/裸 token 子串都能命中
    stats["sub_key_count"] = len(tokens)
    log(f"待写订阅 {len(tokens)} 份（key 名不回显，只记 sha8）")

    if args.dry_run or args.skip_kv_write:
        stats["kv_write"] = "skipped(dry-run)"
        _print_dry_run_summary(stats, families)
        _dump_stats(stats, args)
        return 0

    # ---- 缩量保护 ----
    baseline_count = None
    try:
        first_real = kv.list_keys("sub:") if kv else []
        for key in sorted(first_real)[:1]:
            old_raw = kv.get_value(key)
            old_obj = json.loads(old_raw) if old_raw else None
            baseline_count = count_proxies((old_obj or {}).get("yaml"))
    except Exception as e:
        log("缩量保护基线读取失败（按无基线处理）:", redact(e))
    stats["previous_proxy_count"] = baseline_count
    if baseline_count and new_count < baseline_count * SHRINK_GUARD_RATIO:
        log(f"缩量保护触发: 新 {new_count} < 旧 {baseline_count} 的 70% ⇒ 拒绝覆盖")
        stats["shrink_guard"] = "tripped"
        stats["abort_reason"] = "shrink_guard"
        _write_meta(kv, args, stats)
        return 3
    stats["shrink_guard"] = "passed" if baseline_count else "no-baseline"

    # ---- 写 KV：影子优先 ----
    written, promoted, mismatches = 0, 0, []
    for i, tok in enumerate(tokens, 1):
        real_key = f"sub:{tok}"
        shadow_key = f"{args.kv_prefix}sub:{tok}"
        userinfo = read_userinfo(kv, real_key, shadow_key, os.environ.get("SUB_USERINFO", ""))
        value = kv_value_shape(yaml_text, userinfo)
        target_keys = [shadow_key] + ([real_key] if args.promote else [])
        for tk in target_keys:
            try:
                kv.put_value(tk, value)
                back = kv.get_value(tk)
                if back is None or sha256_of(back) != sha256_of(value):
                    mismatches.append(mask_key(tk))
                    log("回读不一致:", mask_key(tk))
                else:
                    if tk == real_key:
                        promoted += 1
                    else:
                        written += 1
            except Exception as e:
                mismatches.append(mask_key(tk))
                log("写入失败:", mask_key(tk), redact(e))
        if i == 1:
            log(f"首份写入完成（userinfo 长度 {len(userinfo)}，内容不回显）")
    stats["shadow_written"] = written
    stats["promoted_written"] = promoted
    stats["readback_mismatch"] = len(mismatches)
    _write_meta(kv, args, stats)
    log(f"刷新完成: {len(families)} 家族 / {stats['nodes_preferred']} 优选节点 / "
        f"影子 key {written} 份 / 真 key {promoted} 份 / 回读不一致 {len(mismatches)}")
    _dump_stats(stats, args)
    if mismatches:
        return 4
    return 0


def _print_dry_run_summary(stats: dict, families: dict) -> None:
    log("\n===== DRY-RUN 校验 =====")
    problems = []
    nodes_per_family = stats.get("nodes_per_family", {})
    total_nodes = 0
    for fam, target in FAMILY_TARGET.items():
        got_ips = len(families.get(fam, []))
        hard_cap = family_cap(fam)                    # 防跑飞的 IP 硬上限（= target，最坏 1 节点/IP）
        got_nodes = nodes_per_family.get(fam, 0)
        total_nodes += got_nodes
        if got_ips > hard_cap:
            problems.append(f"{fam} IP 数超硬上限 {got_ips}>{hard_cap}")
        if got_nodes > target:
            problems.append(f"{fam} 节点数超目标 {got_nodes}>{target}")
        flag = "" if got_nodes >= target else ("  (未满，候选不足/探活判死)" if got_nodes else "  (空)")
        log(f"  {fam:<8} 目标节点 {target:>3} | IP 硬上限 {hard_cap:>3} | 实得 IP {got_ips:>3} "
            f"| 实得节点 {got_nodes:>3}{flag}")
    for fam in families:
        if fam not in FAMILY_TARGET:
            problems.append(f"非白名单家族出现在池里: {fam}")
    log(f"  优选节点合计 {total_nodes}（目标总和 {sum(FAMILY_TARGET.values())}）"
        f" | X 变体因只探到一条后端而省略 {stats['skipped_x_variants']} 次")
    log(f"  合成 proxy 总数 {stats['proxies_total']} = base {stats['base_backends']} + 优选 "
        f"{stats['nodes_preferred']}")
    log(f"  reality 驼峰修复 {stats['reality_fixed']} 处；候选端口分布 {stats['candidate_ports']}")
    log(f"  丢弃: 非白名单 {stats['quota']['dropped_not_whitelisted']} / "
        f"探活判死 {stats['quota']['dropped_probe_dead']} / "
        f"未测量 {stats['quota'].get('dropped_unmeasured', 0)} / "
        f"池满 {stats['quota']['dropped_all_families_full']}")
    if problems:
        log("  ✗ 校验问题:", "; ".join(problems))
        stats["dry_run_problems"] = problems
    else:
        log("  ✓ 家族配额/端口去重/白名单校验无异常")
        stats["dry_run_problems"] = []


def _write_meta(kv: CFKV | None, args, stats: dict) -> None:
    _dump_stats(stats, args)          # 任何 exit 路径都留证据（exit 2/3/5 原本什么都不留）
    if kv is None or args.skip_kv_write:
        return
    meta_key = f"{args.kv_prefix}meta:last_refresh"
    stats["finished_at"] = now_iso()
    stats["run_id"] = os.environ.get("GITHUB_RUN_ID", "local")
    try:
        kv.put_value(meta_key, json.dumps(stats, ensure_ascii=False, indent=1))
        log("meta 已写入（同影子前缀）")
    except Exception as e:
        log("meta 写入失败:", redact(e))


def _dump_stats(stats: dict, args) -> None:
    try:
        with open("refresh-stats.json", "w", encoding="utf-8") as f:
            f.write(redact(json.dumps(stats, ensure_ascii=False, indent=1)))
    except Exception as e:
        log("stats 落盘失败:", redact(e))


if __name__ == "__main__":
    sys.exit(main())
