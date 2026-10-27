#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""huoge-stats-push.py —— 绕过坏掉的 huoge Worker，独立推送 CF 用量看板到 TG。

背景：huoge-green-lake-6618 的根路径渲染坏了（1101），但 D1（sub_db）里的
凭据与状态都是好的。本脚本直接读 D1 拿凭据，查 CF GraphQL 用量，编辑 TG 里
那条既有的看板消息（_dash_msg_id），并把新总量写回 _dash_last_total。

设计原则：
  - 凭据只在运行时从 D1 读，**不落脚本、不落日志**
  - 只做 editMessageText（同一条消息，不刷屏）；消息不存在才 sendMessage
  - --dry-run 只查不发不写

用法：
  python3 huoge-stats-push.py --dry-run     # 只看数字
  python3 huoge-stats-push.py               # 真发 + 写回
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.parse

ACCOUNT = "d35112200fe417202ce6cbc4ef77ab9e"
DB_ID = "04b7251d-5382-45e8-bb6a-acaa956a0c05"
def _detect_proxy() -> str:
    """本机走 Clash(7897)，GitHub Actions 里直连。显式设 HUOGE_PROXY 可覆盖。"""
    p = os.environ.get("HUOGE_PROXY")
    if p is not None:
        return p
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        if s.connect_ex(("127.0.0.1", 7897)) == 0:
            return "http://127.0.0.1:7897"
    finally:
        s.close()
    return ""


PROXY = _detect_proxy()
TOKEN_FILE = os.path.expanduser("~/.config/cf/scoped-token")


def curl_json(url: str, payload: dict | None = None, token: str | None = None,
              timeout: int = 30) -> dict:
    """用 curl 走代理发请求（本机 urllib 走代理不稳，curl 更可靠）。"""
    cmd = ["curl", "-sS", "--http1.1", "--max-time", str(timeout)]
    if PROXY:
        cmd += ["-x", PROXY]
    if token:
        cmd += ["-H", f"Authorization: Bearer {token}"]
    if payload is not None:
        cmd += ["-H", "Content-Type: application/json", "-X", "POST",
                "-d", json.dumps(payload, ensure_ascii=False)]
    cmd.append(url)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if not r.stdout.strip():
        raise RuntimeError(f"空响应 rc={r.returncode} err={r.stderr[:200]}")
    return json.loads(r.stdout)


def d1_query(sql: str, token: str) -> list[dict]:
    url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/d1/database/{DB_ID}/query"
    d = curl_json(url, {"sql": sql}, token)
    if not d.get("success"):
        raise RuntimeError(f"D1 查询失败: {d.get('errors')}")
    res = d.get("result") or [{}]
    return res[0].get("results") or []


def d1_set(key: str, value: str, token: str) -> None:
    sql = ("INSERT INTO config (key, value) VALUES (?, ?) "
           "ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')")
    url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/d1/database/{DB_ID}/query"
    d = curl_json(url, {"sql": sql, "params": [key, str(value), str(value)]}, token)
    if not d.get("success"):
        raise RuntimeError(f"D1 写入失败: {d.get('errors')}")


GQL = """query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
  viewer {
    accounts(filter: {accountTag: $AccountID}) {
      pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
      workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
    }
  }
}"""


def cf_usage(cf_token: str) -> dict:
    now = time.gmtime()
    start = time.strftime("%Y-%m-%dT00:00:00Z", now)
    end = time.strftime("%Y-%m-%dT%H:%M:%SZ", now)
    payload = {
        "query": GQL,
        "variables": {"AccountID": ACCOUNT,
                      "filter": {"datetime_geq": start, "datetime_leq": end}},
    }
    d = curl_json("https://api.cloudflare.com/client/v4/graphql", payload, cf_token)
    if d.get("errors"):
        raise RuntimeError(f"GraphQL 错误: {str(d['errors'])[:300]}")
    acc = ((d.get("data") or {}).get("viewer") or {}).get("accounts") or []
    if not acc:
        raise RuntimeError("GraphQL 无 accounts 数据")
    a = acc[0]
    pages = sum((i.get("sum") or {}).get("requests", 0)
                for i in (a.get("pagesFunctionsInvocationsAdaptiveGroups") or []))
    workers = sum((i.get("sum") or {}).get("requests", 0)
                  for i in (a.get("workersInvocationsAdaptive") or []))
    return {"total": pages + workers, "pages": pages, "workers": workers}


def tg_call(bot_token: str, method: str, payload: dict) -> dict:
    url = f"https://api.telegram.org/bot{bot_token}/{method}"
    return curl_json(url, payload)


def fmt(total: int, prev: int | None) -> str:
    delta = ""
    if prev is not None:
        d = total - prev
        delta = f"\n今日增量：<b>{d:+,}</b>" if d else "\n今日增量：<b>0</b>"
    return (f"📊 <b>CF 用量看板</b>\n"
            f"今日请求：<b>{total:,}</b>{delta}\n"
            f"更新于 {time.strftime('%Y-%m-%d %H:%M')} (UTC+8)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    token = (os.environ.get("CF_D1_TOKEN", "").strip()
             or open(TOKEN_FILE).read().strip())
    rows = d1_query("SELECT key, value FROM config", token)
    cfg = {r["key"]: r["value"] for r in rows}

    cf_token = cfg.get("CF_TOKEN", "")
    bot = cfg.get("TG_BOT_TOKEN", "")
    chat = cfg.get("STATS_CHAT_ID", "")
    msg_id = cfg.get("_dash_msg_id", "")
    prev_raw = cfg.get("_dash_last_total", "")
    prev = int(prev_raw) if prev_raw.isdigit() else None

    if not cf_token or not bot or not chat:
        print("⛔ D1 里缺 CF_TOKEN / TG_BOT_TOKEN / STATS_CHAT_ID")
        return 1

    u = cf_usage(cf_token)
    text = fmt(u["total"], prev)
    print(f"用量: total={u['total']} workers={u['workers']} pages={u['pages']} | 上次={prev}")

    if a.dry_run:
        print("--- 消息预览 ---")
        print(text.replace("<b>", "").replace("</b>", ""))
        print("(dry-run，未发送)")
        return 0

    ok = False
    if msg_id:
        r = tg_call(bot, "editMessageText", {
            "chat_id": chat, "message_id": int(msg_id), "text": text,
            "parse_mode": "HTML", "disable_web_page_preview": True})
        ok = bool(r.get("ok") or "not modified" in str(r.get("description", "")))
        if not ok:
            print(f"edit 失败: {str(r)[:200]}")

    if not ok:
        r = tg_call(bot, "sendMessage", {
            "chat_id": chat, "text": text, "parse_mode": "HTML",
            "disable_web_page_preview": True})
        if r.get("ok"):
            new_id = (r.get("result") or {}).get("message_id")
            d1_set("_dash_msg_id", new_id, token)
            print(f"已发新消息 message_id={new_id}")
            ok = True
        else:
            print(f"send 失败: {str(r)[:200]}")

    if ok:
        d1_set("_dash_last_total", u["total"], token)
        print("✅ 已推送并写回 _dash_last_total")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
