# 交接文档

最后更新：2026-10-18
覆盖范围：本仓库（RPC/gRPC 扫描 + Cloudflare 注册服务）与 `F:\pallasarb`（套利 bot）的分析结论

---

## 1. 现在的架构

```text
Cloudflare Worker  ←── 会员从这里读（网页 + API）
      ↑ 每 600s 推送
82.23.138.51       ←── 只负责扫描 + 推送，不对外提供任何 HTTP
  rpc_grpc_registry.py  --no-serve
      ↓
  bin/solana-validator-rpc-health.py   真正的探测工具
```

分工要点：**82 只生产数据，Cloudflare 只分发数据**。82 上那个绑 `0.0.0.0:8090` 的 web 已经停掉（该机没有防火墙，`INPUT ACCEPT`，任何 bind 的端口都直接暴露公网）。

### 服务地址

| 组件 | 地址 | 说明 |
|---|---|---|
| 会员入口 | `https://solana-rpc-registry.lwhch888.workers.dev` | 网页 + `GET /rpc` `/grpc` `/all` |
| 扫描机 | `82.23.138.51`（仅 SSH） | 无监听端口 |
| 付费验证 RPC | 4 个公网地址逗号分隔，见下 | `RPC_FOR_VERIFY` |

### 凭据存放位置（**都不写进文档**）

| 文件 | 内容 | 权限 |
|---|---|---|
| `/root/.cf-ingest-token` | 82 推送快照用的 `INGEST_TOKEN` | 600 |
| `/root/.cf-admin-token` | 管理员调 `/admin/*` 用 | 600 |
| `/root/.rpc-registry-password` | 旧 HTTP 的 Basic 密码（现已不用） | 600 |
| 本机 `/tmp/cf_ingest_token.txt`、`/tmp/cf_admin_token.txt` | 同上副本 | 600 |
| wrangler 环境变量 | `CLOUDFLARE_API_KEY` / `CLOUDFLARE_EMAIL` | 不落盘 |

Cloudflare 全局 API Key 的格式是 `cfk_` 开头，**必须配 `X-Auth-Email` + `X-Auth-Key` 两个头**，用 `Authorization: Bearer` 会被判无效（403 Invalid access token）。

### 管理员账号（免付款）

```text
Email    admin@rpcregistry.dev
Password 见运维私聊，未写入本文件
```

激活别人的账号（不走链上支付）：

```bash
curl -X POST -H "Authorization: Bearer <ADMIN_TOKEN>" \
     -H "content-type: application/json" \
     -d '{"email":"someone@example.com"}' \
     https://solana-rpc-registry.lwhch888.workers.dev/admin/accounts/activate
```

离线发 API key：

```bash
/root/solana-validator-rpc-health/bin/mint_key.sh <label> <days>
```

### 常用运维命令

```bash
# SSH 到 82（必须用 key + 直连；详细规则见 skill: server-82-operations）
ssh -i C:/Users/Administrator/.ssh/pallasarb_82_23_138_51_ed25519 \
    -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
    -o 'ProxyCommand=connect -H 127.0.0.1:7897 %h %p' \
    root@82.23.138.51 '<command>'

# 重启扫描（注意：pkill 的模式必须用拼接避开，否则会杀掉自己的 shell）
pkill -f "rpc_grpc_reg""istry"
cd /root/solana-validator-rpc-health/bin
setsid nohup python3 rpc_grpc_registry.py --no-serve --interval 600 \
  --push-race-seconds 10 \
  --push-url https://solana-rpc-registry.lwhch888.workers.dev \
  --push-token-file /root/.cf-ingest-token \
  > /tmp/rpc-grpc-registry/server.log 2>&1 < /dev/null &

# 部署 Worker
cd workers/registry
CLOUDFLARE_API_KEY=... CLOUDFLARE_EMAIL=... \
  npx wrangler@4 deploy --config wrangler.jsonc
```

> 82 的 SSH 走 `ProxyCommand=connect -H 127.0.0.1:7897`，直连会 `Network is unreachable`。
> 但 **GitHub 走 HTTP 代理** `http://127.0.0.1:7897`。两者是不同的东西，别搞混。

---

## 2. 今天最重要的发现：Cloudflare 只放行 80 和 443

给 Worker 加了临时探测入口逐目标实测（该入口已删除，见 §6）：

| 目标 | 端口 | 结果 |
|---|---|---|
| `https://1.1.1.1` | 443 | 200 / 46ms ✅ |
| `https://solana-rpc.publicnode.com` | 443 | 200 / 66ms ✅ |
| `http://1.1.1.1` | 80 | 200 / 29ms ✅ |
| `http://www.example.com` | 80 | 405（到得了）✅ |
| `http://185.191.117.10:8899` | 8899 | **403 / 2ms** ❌ |
| `http://134.119.214.42:8899` | 8899 | **403 / 2ms** ❌ |
| `http://64.130.47.151:10000` | 10000 | **403 / 2ms** ❌ |
| `https://134.119.214.42:8443` | 8443 | **403 / 2ms** ❌ |

**判据是那 2 毫秒**：响应头带 `cf-ray: ...-HKG`，说明是 Cloudflare 自己的边缘返回的，请求根本没离开 CF 网络。跨洋往返不可能 2ms。

```text
规则：80 和 443 放行；其余端口 → error code: 1003 → 直接拒绝
而我们扫的正是 8899（RPC）和 10000（gRPC）
```

### 结论：Worker 不能替代扫描，三条独立阻塞

| 阻塞 | 原因 | 影响 |
|---|---|---|
| **端口白名单** | 只有 80/443（实测，见上） | 扫不到 8899/10000 |
| **无子进程** | V8 isolate，没有 `child_process` | 没法跑 `grpcurl` |
| **无原始 TCP socket** | 只有 `fetch()` | 拿不到 `TCP_INFO.tcpi_rtt`；没法发 h2c 前导字节；做不了 3737 IP × 6 端口 ≈ 2.2 万次连接 |
| **gRPC trailer** | Workers 的 `fetch()` 只给 `response.headers`，拿不到 trailer | gRPC 把 `grpc-status` 放在 trailer 里，区分不出「正常」和「要 token」 |

四条里**任何一条**都足以否决。而且最关键的两样——**内核 RTT** 和 **gRPC 真推流验证**——恰是产品卖点。

> **`TCP_INFO` 为什么不可替代**：82 那台负载 80-90%，用户态计时会因为进程被调度延迟而严重失真。内核在收包瞬间打的时间戳不受影响，这才是那些 0.8ms 数据的来源。

### Worker 能做什么

Cron Trigger 定时**复检已知的 HTTPS 端点**可以做。但会丢掉三样：发现新端点、内核 RTT 排序、gRPC 推流验证。**扫描留在 82，或另找一台机器。**

---

## 3. Cloudflare 的其他实测约束

| 约束 | 表现 | 应对 |
|---|---|---|
| **PBKDF2 迭代上限 100000** | 设 150000 报 `NotSupportedError: iteration counts above 100000 are not supported` | 已设为 100000（上限） |
| **`api.mainnet-beta.solana.com` 封 CF 出口** | `Your IP or provider is blocked from this endpoint` | 改多地址故障转移 |
| **对外 fetch 到 raw IP** | 见 §2，受端口限制 | 付款验证走域名 + 443 |
| **`X-Robots-Tag`** | 无 | 见 §5 |

### 付款验证的 RPC 故障转移

```jsonc
"RPC_FOR_VERIFY": "https://solana-rpc.publicnode.com,..."
```

- 逗号分隔，按顺序尝试
- **能解析出 JSON-RPC（含 `result` 或 `error`）就视为权威并停止**，即使是 `result: null`
- 只有传输失败（网络错、非 JSON 响应如 CF 的 HTML 错误页）才切下一个
- `https://solana-rpc.publicnode.com` **实测从 Worker 可通**，建议排第一

---

## 4. 扫描方法论的重要发现

### 4.1 只扫「广告 RPC IP」会漏掉绝大部分 gRPC

这是今天最大的方法论教训。

```text
只扫 getClusterNodes 里 advertised RPC 的 IP   → 找到 1 个 h2c 候选
扫全部 getClusterNodes 的 gossip/rpc/tpu IP     → 找到 299 个 h2c 候选
```

`getClusterNodes` 返回 ~3700 个节点的三类地址（`gossip` / `rpc` / `tpu`），**大部分节点不广播 rpc 端口，但可能跑着 gRPC**。之前的扫描方式把 99% 的 gRPC 排除了。

已改为：取全部三类地址去重，扫 6 个常见端口（10000/10001/10002/8080/8000/8001）。

### 4.2 「端口开着」≠ gRPC，必须做协议验证

227 个开放端口里只有 **1 个**真 HTTP/2：

```text
146  ConnectionReset     非 HTTP/2
 43  HTTP/1.1            是普通网站反代（ASCII `485454502f312e31` = "HTTP/1.1"）
 36  空响应
  1  http2-settings      ← 只有这个
```

### 4.3 可用 gRPC 的三级判据（缺一不可）

```text
① HTTP/2 前导 → 收到 SETTINGS 帧
② geyser.Geyser/GetVersion 返回 Yellowstone 版本
③ 匿名 geyser.Geyser/Subscribe 实际收到流数据
```

**`GetVersion` 通过不代表能用**——第 ③ 级才排除「只握手不推流」。另外需 token 的端点要**剔除**（只留计数），不能混进主列表。

一次全量扫描的典型结果：

```text
h2c 候选 300 → GetVersion 通过 63 → 订阅通过 55 → 需认证 24（剔除）
185 个是 HTTP/1.1 网站（403），20 个是 HTTP/2 但非 Yellowstone
```

### 4.4 分类器的两个坑（都踩过）

- **正则写错**（`re.error: unterminated character set`）导致 `USABLE = 0` 的假结果，实际有 64 个
- **`Subscribe` 是永流**，grpcurl 到 `-max-time` 必然以 `DeadlineExceeded` 退出。若把 `deadline` 判定放在成功证据之前，**64 个全被判成超时**。必须先看有没有收到 `filter` / `"slot"` / `ping`。

### 4.5 RPC：多数健康节点是「阉割版」

```text
广告 286 → 健康 ~37 → 三方法齐全 只有 1 个
```

那 2ms 的快节点（`185.191.117.10`、`70.40.186.125`、`51.89.11.213`…）**只支持 `getHealth` / `getSlot` / `getVersion`**，`getLatestBlockhash` 和 `getMultipleAccounts` 全部 `-32601 Method not found`。

原始 curl 独立复验过，不是探测工具的问题。**它们只能当健康监控，不能做交易。**

目前唯一三项齐全的公开节点：

```text
http://134.119.214.42:8899   rpc 8ms   ver 4.3.0
```

（注意：它在某几轮扫描里会掉到 0 可用，因为是单点。）

### 4.6 推送滞后（`push_lag_ms`）才是有效排序指标

每个 Yellowstone `SubscribeUpdate` 自带服务端 `createdAt`：

```text
age_ms = (本地接收时间 − createdAt) × 1000
每个端点取中位数（丢弃 -1000 ~ 60000 之外的时钟偏移样本）
```

比 `GetVersion` 往返延迟更接近真实体验，也**不受其他端点互相竞争影响**（slot race 需要 400ms 粒度，这个是毫秒级）。

典型值：`min 2.1ms / p50 6.4ms / p95 64ms`。

---

## 5. 修复的 bug（都有过真实后果）

### 5.1 扫描线程静默死亡（**最严重**）

```text
表现：进程活着、端口在听、返回 200，但数据是 62 小时前的
根因：scan_loop 无异常保护，一次偶发失败（日志里有 HTTP 429）
      → 守护线程永久退出 → 而 HTTP 服务继续回 200
```

**教训：一个回 200 的服务不等于数据新鲜**。现在：

- `scan_loop` 用 `BaseException` 兜住（实测扛过 `RuntimeError`/`KeyboardInterrupt`/`SystemExit`/`ZeroDivisionError`/`MemoryError`）
- `/health` 暴露 `consecutive_failures` 和 `last_success_at`
- 错误消息截断到 300 字符（原本会把整个子进程 traceback 存进快照再由 `/health` 吐出来）
- 固定周期：原来是「扫完再睡 600s」，实际周期 11-14 分钟；改为扣掉扫描耗时

> **同一类故障在 pallasarb 也发生过**（见 §7），那边一次本地 socket 错误导致进程停摆 3 小时 17 分。

### 5.2 代码分叉（服务器上有 5 个 `.bak` 手工备份）

```text
修复前：服务器 1384 行（不在 git 里） vs 本地 1195 行
       各有各的修复，谁都不完整
现在：  合并进一个文件，服务器从 git 部署
```

### 5.3 付款验证的三个错

| 错误 | 后果 |
|---|---|
| `maxSupportedTransactionVersion: 0` | 现在区块常见 v1 交易，请求 0 让 RPC 整块拒绝（`-32015`），表现像验证器坏了。已改 `1` |
| 按 USDC 查余额，但收款是 SOL | 本来会永远验证失败。改为查原生 SOL 余额前后差 |
| 单一 RPC | `api.mainnet-beta` 封 CF 出口 + `82.39.215.201` 仅内网 → 一个能用的都没有。已加故障转移 |

### 5.4 Durable Object 的三个坑

```text
① 没继承 DurableObject 基类 → RPC 调用在 stub 上根本不执行
② DO 的 RPC 永远返回 Promise（哪怕方法是同步的）→ 一整套方法没 await
   → has_snapshot: true 但字段全 null
③ getSnapshot 解析一次、调用方又解析一次 → 重复 JSON.parse 抛异常
```

### 5.5 Cloudflare 拒绝 Python urllib

```text
Python urllib  → 403 error code: 1010（浏览器指纹检测）
curl           → 200
```

两个推送脚本（`rpc_grpc_registry.py` 的 `_push_to_cloud`、`bin/cf_push.py`）都已改成走 `subprocess + curl`。

> 诊断方法：同一目标分别用 urllib 和 curl 打，一有 1010 一有 200 就是这个问题。

### 5.6 其他

- `HEAD /` 返回 404（只实现了 `do_GET`）——爬虫和健康检查常用 HEAD 探路，已修
- `pkill -f rpc_grpc_registry.py` 在同一条命令里**自匹配**，把远程 shell 自己杀了（exit 255）。必须用拼接技巧：`pkill -f "rpc_grpc_reg""istry"`
- Worker 的 `PBKDF2` 迭代上限 100000（见 §3）

---

## 6. 安全相关

### 6.1 曾出现的 SSRF（已处理）

为了实测端口限制，给 Worker 临时加过一个 `GET /probe?u=<任意URL>`，它会**以你的 Worker 身份去 fetch 任意目标**——这是标准 SSRF。

处理：**已删除并部署（现返回 404），且从未提交进 git**（`git grep '"/probe"' HEAD` = 0）。

> 教训：调试用的回显/代理入口必须用完即删，不要进版本控制。

### 6.2 传输是明文 HTTP（内网才算可接受）

Basic 凭据只是 base64 **编码**，不是加密。举个无关真实凭据的例子：

```text
明文       user:xxxxxxxx
Base64     dXNlcjp4eHh4eHh4eA==
```

`echo '<base64>' | base64 -d` 一条命令就还原。同样的对照：

```text
echo 'YWRtaW46cGFzc3dvcmQxMjM=' | base64 -d   →   admin:password123
```

所以：

- 8090 那条路径**已经停掉**（见 §1），公网不再暴露 Basic 认证
- 仍以明文传输的是 Worker → 82 的快照推送，只带 `INGEST_TOKEN`，且是单向推送
- 要把这个也加密，就得让 82 出网走 TLS 或反过来由 CF 主动拉取

### 6.3 该机没有防火墙

```text
iptables INPUT ACCEPT，无 ufw/nft filter 规则
任何 bind 0.0.0.0 的端口 = 立刻公网可达
```

这是把 8090 停掉的主要原因。

---

## 7. 跨仓库：pallasarb 套利 bot 的分析结论

仓库 `F:\pallasarb`，远端 `wuhanwuyanzu123/pallasarb`（**私有**，未认证 API 返回 404）。

### 7.1 结构性结论：路线本身不赚钱

```text
路线  enra-sol-pumpswap-meteora   （SOL → T1YZ…pump → SOL，跨 DEX 同一对）
两跳手续费  PumpSwap 25bps + Meteora 25bps + 协议/创建者费
实测报价    -60 ~ -75 bps（三个数量级的 amount 都是同一水位）
执行门槛    min_profit 50000 + tip 1707 + 费 5000 + 优先费 ≈ +57 bps
             ↓
缺口约 127 bps —— 不是配置能补的
```

`edge_bps` 在 `main.rs:3203-3210` 计算，**是纯报价比值，没有任何折扣**，所以 -60bps 就是 Pallas 路由器自己在说亏钱。

绑定闸门是 `below_min_profit_plus_costs`（`main.rs:3282-3298`）。日志里 **5712 次 `PALLAS_POLL`、5712 次 `PALLAS_CYCLIC`、零次 `PALLAS_EXEC_*`**——因为旧代实现是**静默 `continue`**，一个字都不打。

### 7.2 为什么会落到 `MinReturnNotReached`（instruction 7）

指令序（来自解码的 Pallas 响应）：

```text
0 Jito tip → 1 SetComputeUnitLimit → 2 SetComputeUnitPrice
3 ATA → 4 ATA → 5 flashloan borrow → 6 swap → 7 收腿 swap → 8 payback
```

**index 7 = 闭环的收腿（本路线是 meteora leg）**，`min_return` 由 OKX 路由器算好塞进 base64，**客户端改不了**。

三个导致它失败的原因：

1. **滑点只有 1bp**（`pallas_slippage_percent` 默认 `0.01`%），一个 slot 的波动远超它
2. **sim 与 send 之间无重新报价、无陈旧度检查**——`quote.context_slot` 只被打印，从不校验
3. 用的是 **Pallas 随附的陈旧 blockhash**（引擎 ~2s 缓存，签名时已落后 2-8 slot）

### 7.3 其他风险点

- `--random-amount` 模式下每次抽新金额 + 新优先费，选择是后验的
- `Lighthouse profit guard` **默认关闭**，且即便开启它在 index 7 **之后**，挡不住 6010，只能把亏损变成回滚
- **落链失败是孤儿**：`log_pallas_signature_confirmation` 只打印不解析 `6010`，没有连续计数、没有退避、没有收紧 `dex_ids`
- 无重试逻辑（`main.rs:4322` 注释提到"下面的 retry quote"但代码里没有）

### 7.4 本次拉取的 4 个提交（已完成 `--ff-only` 合并）

| 提交 | 内容 | 关键数据 |
|---|---|---|
| `353a141` | 按利润算 Jito tip + 批量 landing 审计 | 落地检测从**每次 40 个 RPC** 改为 Jito `getInflightBundleStatuses`（5 个/500ms），拿到官方 Landed/Failed/Invalid |
| `0033849` | 每次发送用新鲜 blockhash（opt-in） | 发现 Pallas 附带 blockhash 落后 2-8 slot |
| `7245f37` | **修宕机 3h17m** | `?` 冒泡把本地 `os error 99 EADDRNOTAVAIL` 带出循环 → 进程退出。改为记 `PALLAS_BLOCKHASH_FETCH_FAILED` 并跳过该报价，**不静默回退**。同时共享连接池，p50 10ms→5ms |
| `d9b2737` | 每次发送只查一次 slot | 9 个端点原本各查一次（只为填日志）。改 `Arc<OnceLock<u64>>` 共享。`TIME_WAIT` 从 ~406 降到 ~200-270 |

> **`7245f37` 最重要**，和 §5.1 是同一类故障：一个意外异常不该让核心循环退出。
> 拉取改了 `src/main.rs`(+457)、`tx.rs`、`pallas.rs`，**要用必须重新编译**。bot 当前没有进程在跑。

---

## 8. 待办 / 已知未完成

| 项 | 状态 |
|---|---|
| Google 收录 | **未收录**（`site:` 查询 0 条链接）。robots 无 Disallow，但也没 `search:` 信号。`*.workers.dev` 域名权重低、无外链。**可挂自己的 7 个域名**（见 Cloudflare zone 列表），比 workers.dev 友好得多 |
| 支付成功率 | 逻辑已用真实交易端到端验证过，但**没有真实付费用户跑过** |
| 扫描机资源 | 82 CPU 已 80-90% 饱和，扫描占 4 核。可考虑搬去独立 VPS 或 GitHub Actions cron |
| `bin/rpc_grpc_registry.py` 无 systemd | 现为 `setsid nohup`，**重启机器不自动恢复** |
| 存储迁移 | Cloudflare 用 Durable Object (SQLite)；82 侧的 `last-scan.json` 是本地文件 |

---

## 9. 相关文件

```text
workers/registry/src/index.js          Worker 主体（DO + 账号 + 付款 + 路由）
workers/registry/src/dashboard.html    仪表盘（英文，四视图）
workers/registry/wrangler.jsonc        配置（PAY_TO / PRICE_SOL / RPC_FOR_VERIFY）
bin/solana-validator-rpc-health.py     探测工具（无第三方依赖）
bin/rpc_grpc_registry.py               扫描 + 推送循环（--no-serve）
bin/cf_push.py                         独立推送脚本
bin/mint_key.sh                        离线发 key
docs/HANDOVER.md                       本文档
```

---

## 10. 今日提交

```text
0434311  Run the scanner without binding an HTTP port
1b23547  Serve HEAD on the landing page
3992246  Let an operator activate an account without paying
6b862a6  Take payment in SOL instead of USDC
4b69912  Sign up first, pay after; move the UI to English
20be23f  Add a landing page ahead of the key gate
d7bcac0  Serve the registry from Cloudflare Workers
2df6eba  Merge push-lag measurement and kernel RTT from the deployed copy
cdf40ee  Stop the scan thread from dying silently
```

`F:\pallasarb`：`e34ab36 Add remaining local diagnostic scripts`（13 个），并快进合并了远端 4 个提交。
