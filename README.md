# sub-pool-builder

把原来跑在 Cloudflare Worker（`sub-server` v10）里的「抓上游优选 IP → 探活 → 合成 clash 订阅」
这一段搬到 **GitHub Actions** 上执行，Worker 之后退化成只从 KV 读配置分发的纯分发器。

搬家的原因：Workers 免费档一次调用只给 50 个子请求 / 10ms CPU，做不了完整协议握手探活，
v10 只能用「明文 `http://IP:443` 有响应」当存活判据 —— 实测 AWS / 腾讯 / HiNet / A2B / 中华电信
这些**非 CF 源站同样回 400**，于是整批假活节点被塞进订阅，客户端连上必死。
Actions runner 没有这个限制，所以这里做的是**三层真探活**。

## 三层真探活（本仓的核心）

对每个候选，按**它自己带的端口**和**它自己将要使用的后端**逐层验：

| 层 | 做法 | 判活标准 | 超时 |
| --- | --- | --- | --- |
| ① TCP | `socket.create_connection(ip, port)` | 能建连 | 4s |
| ② TLS | `ssl` handshake，**SNI = 后端域名** | 握手完成 | 4s |
| ③ WS | 在同一 TLS 连接上发 `GET <path> HTTP/1.1` + `Host=<节点自身 Host>` + `Upgrade: websocket` | **只认 HTTP/1.1 101** | 4s |

* ⛔ 绝不把「任何 HTTP 响应（含 400）」当存活。
* 并发 ≤50（`asyncio` 信号量 + 线程池跑阻塞 IO），单候选失败重试 1 次；
  一个候选探到 2 条后端（主节点 + X 变体各一条）即短路，省握手。
* 连的是 CF 优选 IP，证书 CN 与 IP 必然不匹配 ⇒ ② 关闭证书校验（只验握手能否完成，
  不传任何数据，无 MITM 风险面）；SNI 必须真发出去，因为 CF 边缘按 SNI 路由。
* TLS/WS 失败 ⇒ 只有那一条后端记死；TCP 失败 ⇒ 该 `(ip, port)` 所有后端直接判死。

## 修掉的 v10 五个 bug

| # | v10 症状 | 这里改在哪 |
| --- | --- | --- |
| 1 | `ONLY_US=true` 分支写死家族名「战争贩子」，不在 `FAMILY_TARGET` ⇒ 回退 cap 120 IP = 240 节点打爆配额 | `ONLY_US_FALLBACK_FAMILY = "美国"` + `assign_families()` 只允许标准名，`family_cap()` 对表外家族返回 0 |
| 2 | rr 轮转不认满员：先满员的家族之后的轮次整条丢弃，不顺延给同地区另一家 ⇒ 配额吃不满、随上游顺序漂移（现网 港岛茶记18 / 香港20 非对称） | `pick_family()`：跨家族共享候选池，保留轮转起点但满员即顺延，各家族各自填到**节点目标** |
| 3 | 去重键 `ip\|品牌` 不含端口 ⇒ 同 IP 的 443 / 2096 两行互相吞掉 | `dedup_candidates()` 键为 `ip\|brand\|port` |
| 4 | 每 IP 产 2 节点（主 + X），`FAMILY_TARGET` 记的是最终节点数 | 填充闸门直接按**节点数**算（`family_nodes()`），`family_cap()` 退化为防跑飞的 IP 硬上限（= target，最坏 1 节点/IP）；末位不足目标时把该 IP 的 `passes` 截到剩余名额，**永不超配** |
| 5 | `probeAll` 只按 443 探，无视候选自带端口（2053/2083/2096/8443 全被错探） | 探活以 `(ip, port)` 为单元：`probe_one_combo_sync(ip, port, backends, …)` |

> 为什么 #4 要改成按节点填：v10 与初版迁移稿都按「IP 槽位 = ceil(target/2)」收人，但 X 变体只在
> **两条后端都探活**时才生成。只探到一条的 IP 白占一个槽位却只出 1 个节点 ⇒ 家族永远填不满
> （dry-run 实测 106/150）。改成节点口径后 dry-run 恰好 150/150，且仍不会把 60 个 IP 塞成 120 节点。

另：`profile-update-interval` 由 `1` 改 **`6`**（与 6h cron 对齐）。它是分发器 Worker 的响应头，
不写进 KV 值（值形状固定为 `{yaml, userinfo}`），常量 `PROFILE_UPDATE_INTERVAL` 留给 S6 改 Worker 时用。

## 数据流

```
16 路上游源（照搬 v10：7 品牌 + 3 地区 + 6 路 gslege；GITHUB_SOURCES 保持置空）
  → dedup(ip|brand|port)
  → 正对照：先拿 base 里的真实 ws 后端走一遍三层，全灭 ⇒ 判测量通道故障，退出码 5、不写 KV
  → 三层探活（≤ --probe-limit 个 (ip,port)，超出按「未测量」拒收）
  → 家族配额（按节点数填到目标，共享池 + 满员顺延；未测量的候选一律不收）
  → build_config(base, families)：克隆 ws 后端模板，主节点 + X 变体
  → 缩量保护（新节点数 ≥ 上一版 70% 才放行）
  → 写 CF KV：默认只写影子 key test:sub:<token> + test:meta:last_refresh
```

两道 fail-closed 闸门是本轮验收时补的，别当成可选项：

* **正对照**（`run_positive_control`）：Actions 出口若被限流/防火墙拦了 443 出站，所有候选都会
  「探不到」，存活率闸门只会告诉你「源面故障」——但那其实是**我这把尺子断了**。对照组全灭直接
  退出码 5，本次不许产出任何生死结论（判据出自失误台账 L2 第⑤条）。
* **未测量 = 拒收**：初版是 `pr is not None and not pr.passes` 才判死，即「没拿到探测结果」的候选
  被当存活放行、还会拿全部后端组节点。现在缺结果就单独计数 `dropped_unmeasured` 并拒收。

上游源清单 1:1 照搬 v10，**没有增删、没有自创**；`hostmonit`/`cfyes` 的 key 只从 secret `CFYES_KEY` 读。

## KV 写入约定（写错 Worker 就 404）

* 值形状固定为 JSON 对象字符串：`{"yaml": "<配置JSON文本，字符串字段>", "userinfo": "<空格分隔原样串>"}`；
  `userinfo` 从现存订阅原样透传，⛔ 不改成分号分隔。
* 绑定名 `SUB_KV`，命名空间 title `sub-server-SUB_KV`（可用 var `KV_NAMESPACE_TITLE` 覆盖）。
* **影子 key 优先**：`--kv-prefix` 默认 `test:`，S1–S5 只写 `test:sub:<token>`；
  真 key `sub:<token>` 只在显式 `--promote` 时写。`--kv-prefix ''` 且没勾 `--promote` 会被直接拒绝执行。
* 每次写完立刻 GET 回读比 sha256，不一致退出码 4。
* CF 访问走原始 REST API（`https://api.cloudflare.com/client/v4/…`），⛔ 不依赖 wrangler
  （本机 macOS 12 的 workerd 跑不起来，CI 里也没必要装）。account id 与 namespace id
  **一律从当次 API 响应里取**，代码里没有任何账号 id / NS id 的字面值。

## Secrets / Vars 清单

| 类型 | 名称 | 必需 | 用途 |
| --- | --- | --- | --- |
| secret | `CF_API_TOKEN` | 写 KV 时必需 | CF #2 账号的 KV 读写 token（Workers KV Storage Read&Edit） |
| secret | `CFYES_KEY` | 是（少它就跳过 hostmonit 源，不中断整轮） | hostmonit `get_optimization_ip` 接口 key |
| secret | `SUB_USERINFO` | 否 | KV 里没有现存订阅时的 userinfo 兜底串 |
| var | `CF_ACCOUNT_ID` | 账号多于 1 个时必需 | 只在本次 `/accounts` 响应里匹配，匹配不上直接报错 |
| var | `KV_NAMESPACE_TITLE` | 否 | 默认 `sub-server-SUB_KV` |
| var | `DEAD_DOMAINS` | 否 | 逗号分隔死域名清单；命中 base 只在 `meta` 里记次数，本脚本不改 base |
| var | `ALERT_NTFY_TOPIC` | 否 | 配了才启用「连续 2 次失败」ntfy 告警 |
| var | `UPLOAD_CONFIG_ARTIFACT` | 否 | 默认不上传产物 —— 产物里有 VLESS uuid，属凭据 |

⛔ 仓库、README、代码、日志、`meta:last_refresh`、`refresh-stats.json` 全部零凭据：
token / key / 订阅 URL / userinfo 原文一律不回显（所有日志过 `redact()`，key 名只打 sha8）。

## 运行方式

```bash
# 本地自检：完全不联网，用内置样本验配额/端口去重/白名单/reality 驼峰修复
python3 -m py_compile build.py
python3 build.py --dry-run
python3 build.py --dry-run --only-us true

# Actions（cron '20 */6 * * *' + workflow_dispatch），影子 key
# 手动 dispatch 可勾 dry_run / promote / only_us，并可改 kv_prefix、min_alive_ratio

# 验收通过后把终版复制进真 key（S6，之后还要撤掉旧 Worker 的 scheduled 与 6h cron 触发器）
python3 build.py --promote
```

主要开关：`--kv-prefix` `--promote` `--tokens` `--base-from` `--out` `--only-us`
`--workers` `--timeout` `--retries` `--min-passes` `--probe-limit` `--min-alive-ratio`
`--no-probe` `--skip-kv-write` `--dead-domains`。

退出码：`0` 正常 ｜ `1` 致命（凭据/base 缺失）｜ `2` 存活率 <30% 或池空 ⇒ **源面故障，不写 KV**
｜ `3` 缩量保护触发 ⇒ 保留旧配置 ｜ `4` 写后回读 sha 不一致 ｜ `5` 正对照全灭 ⇒ **测量通道故障**。

## 可观测与故障保护

* **正对照全灭 ⇒ 退出码 5**（测量通道坏了，本次不产出任何存活结论）。
* 聚合存活率 <30% ⇒ 判源面故障：不写 KV、退出码 2。
  ⚠ 这里**故意不照搬 v10**：v10 是 `alive < PROBE_MIN_ALIVE` 就「回退全量候选」，
  等于把没验证过的 IP 直接推上线（日志里那句 `探活: 0/N … 回退全量` 就是它）。本脚本改成停写。
* 逐源失败计数（`ok` / `count` / `last_error`）写进 `test:meta:last_refresh`。
  Actions 出口是 Azure 数据中心 IP，**同源连续多轮失败先怀疑 hostmonit/4ce 限流，不等于节点死**。
* 缩量保护基准：优先按**要写的那个 token** 的现存版本比，取不到再退到 `sub:` 前缀第一个 key
  （v10 只取第一个，多 token 时基准可能不是现网最新版）。

## 现在的状态（2026-10-16 更新）

* ✅ S0 凭据：CF #2 的 KV+Scripts 可写 token 已取到（不进仓库，只进 GH Secrets 与本机 0600 文件）。
* ✅ S0.5 诊断：线上确认跑的就是 v10，且 `17 */6 * * *` cron **存在并在跑** ⇒ 本任务是**纯迁移**，
  不是「迁移+修史」。附带发现：v10 **从不写 `meta:` 键**，所以验收②的 `last_refresh` 由本脚本新增实现。
* ⏳ S1–S5：影子 key 链路实跑与验收。
* ⏳ S6：切真 key + 删 Worker 的 scheduled/抓取分支 + 撤旧 6h cron + `profile-update-interval` 1→6，
  最后回用户本机经真实代理链路抽查 20 节点。

## 还没做 / 需要人工接手

* base:config 死域名清理属 S4：脚本只做计数告警（`--dead-domains`），不改写 base。
* 连续失败告警通道（ntfy topic 或邮箱）还没配 —— `ALERT_NTFY_TOPIC` 不配就是不告警，等用户点名。
* 探活结论来自美/欧数据中心，对「墙内真实可用」只是间接证据：验收第④条必须回用户本机
  走真实代理链路抽查（Clash Verge 选节点 → curl 204），不在本脚本范围内。
* ⛔ 本脚本从不主动写真 key，除非显式 `--promote`；旧 Worker 的 6h cron 撤掉前，
  双轨只写 `test:` 前缀互不打架。
