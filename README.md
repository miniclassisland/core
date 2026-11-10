# MINI ClassIsland Backend Core (`miniclassisland/core`)

<p align="center">
  <a href="https://miniclassisland.com" target="_blank" rel="noopener noreferrer">
    <img src="assets/miniclassisland.png" alt="MINI ClassIsland Logo" width="128" height="128" />
  </a>
</p>


> **MINI ClassIsland** 集控核心后端 — Python 异步实现  
> 完整实现 [Cyrene_MSP 协议 v2.0.0.0](https://github.com/ClassIsland/ClassIsland/tree/master/doc/Design/Cyrene_MSP)，面向千级租户、万级并发终端场景。

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Test Coverage: 100%](https://img.shields.io/badge/coverage-100%25-brightgreen)](tests/)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-green)](LICENSE)

---

## 1. 概述

**MINI ClassIsland Backend Core** 是 [ClassIsland](https://github.com/ClassIsland/ClassIsland) 的集中管理后端服务，为中小学、教育集团及教研室提供多租户校园终端设备管控能力。它通过三个职责隔离的 FastAPI HTTP 服务（`:27041`、`:27042`、`:27043`）与一个异步 gRPC 服务（`:27044`）协同运行，实现课表与策略下发、双向实时指令流、远程运行日志与配置抓取、审计事件解码存储以及租户配额治理。

---

## 2. 技术栈

| 组件 | 技术选型 |
| :--- | :--- |
| **HTTP API 框架** | [FastAPI](https://fastapi.tiangolo.com/) + [Uvicorn](https://www.uvicorn.org/) |
| **实时双向通信** | [gRPC AsyncIO (`grpcio`)](https://grpc.io/) + `grpcio-reflection` |
| **ORM 与数据库** | [SQLAlchemy 2.0 (Async)](https://www.sqlalchemy.org/) + [PostgreSQL (`psycopg` v3)](https://www.postgresql.org/) |
| **缓存与分布式会话** | [Redis (`redis[hiredis]`)](https://redis.io/)（分库隔离：DB0 认证、DB1 设备会话、DB2 租户缓存） |
| **协议序列化** | [Protocol Buffers 3](https://protobuf.dev/) |
| **密码学与签名** | [PGPy](https://pgpy.readthedocs.io/) (2048-bit RSA OpenPGP) + [Argon2id (`argon2-cffi`)](https://argon2-cffi.readthedocs.io/) + [PyOTP](https://pyauth.github.io/pyotp/) |
| **CLI 与包管理** | [Typer](https://typer.tiangolo.com/) + [uv](https://docs.astral.sh/uv/) |

---

## 3. 四端口服务与架构设计

| 端口 | 模块路径 | 服务名称 | 核心功能说明 |
| :---: | :--- | :--- | :--- |
| **`:27041`** | [`app/client/`](app/client/) | **Client API** | 面向教室内 ClassIsland 终端：提供 `/api/v1/client/{client_uid}/manifest` 清单生成、一次性令牌资源下载（`/get?token=...`）与内嵌字体下载（`/fonts/{filename}`）。 |
| **`:27042`** | [`app/management/`](app/management/) | **Management API** | 面向租户管理员与教务人员：认证与 2FA (TOTP/恢复码)、租户创建、7 类配置资源 CRUD（`ClassPlan`、`TimeLayout`、`Subjects`、`DefaultSettings`、`Policy`、`Components`、`Credentials`）、终端准入（开放/6位配对码/预注册白名单与 CSV 批量导入）、单点/广播通知与命令推送、远程配置/日志抓取、审计日志与成员角色管理。 |
| **`:27043`** | [`app/admin/`](app/admin/) | **Admin API** | 面向平台超级管理员：首次启动 OOBE 向导（`/oobe/verify`、`/oobe/configure`）、$O(1)$ 全局统计指标（`/stats`）、全平台用户与注册审批、租户生命周期与配额管理（`AccountQuota`）、系统全局开关配置。 |
| **`:27044`** | [`app/grpc/`](app/grpc/) | **Cyrene_MSP gRPC** | 面向 ClassIsland 客户端的实时协议层：`ClientRegister`、`Handshake`、`ClientCommandDeliver`、`ConfigUpload`、`Audit`。 |

### 上游 Cyrene_MSP v2.0.0.0 协议完整实现

| gRPC 服务 | 状态 | 详细机制 |
| :--- | :---: | :--- |
| **`ClientRegister`** | ✅ 已实现 | 支持 `open`（开放自动准入）、`pairing`（6 位动态配对码人工审批）、`pre_reg`（按 `ClientId` 或硬件 `MAC` 匹配预注册白名单并自动绑定预设档案）三种模式，返回服务端 OpenPGP 公钥，并校验硬件 MAC 防篡改。 |
| **`Handshake`** | ✅ 已实现 | `BeginHandshake` 使用线程池异步解密客户端 RSA 挑战令牌（`asyncio.to_thread` 避免阻塞事件循环）；`CompleteHandshake` 验证挑战令牌并颁发 24h 会话 `SessionId`（含 L1 内存 + Redis 双层缓存）。 |
| **`ClientCommandDeliver`** | ✅ 已实现 | `ListenCommand` 双向长连接流：处理客户端 `Ping`/`Pong` 心跳（内置节流与 20s 周期 Redis 续期），实时下发 `RestartApp`、`SendNotification`、`ForceSyncConfig`、`UpdateClientConfig`、`GetClientConfig` 指令，并在断线重连时自动迁移未投递指令。 |
| **`ConfigUpload`** | ✅ 已实现 | `UploadConfig` 支持最高 **2 MB** 负载上传（完整容纳上游 `AppLogService` 1,000 条 `LogEntry` 运行日志快照及大型课表配置）。兼容上游无 Session Metadata 的实现，通过 `RequestGuidId` 状态机结合终端会话或注册 IP 严格鉴权。 |
| **`Audit`** | ✅ 已实现 | `LogEvent` 接收客户端上报的 17 类审计事件（课表切换、授权验证、设置修改等），自动解码 Protobuf 负载为结构化 JSON（[`app/shared/utils/audit.py`](app/shared/utils/audit.py)）并持久化至 `audit_logs`。 |

---

## 4. 高并发性能与安全加固特性

- **双层缓存（L1 Memory + L2 Redis）**：
  - 租户子域名解析（`resolve_account`）与 gRPC 设备会话校验（`validate_session` / `get_session_tenant`）均内置进程内 TTL 缓存，将数千客户端并发握手、建流与心跳期间的 Redis 往返开销降至最低。
  - `:27041/get` 接口内置 `_NORMALIZED_RESOURCE_CACHE`，按 `(account_id, resource_type, name, version)` 缓存规范化 JSON 响应，避免在大规模全校同步时重复执行 `json.loads` 与 `normalize_resource_payload`。
- **$O(1)$ 在线状态与配额统计**：
  - 超管 `/stats` 与租户 `max_grpc_connections` 配额检查直接读取 `ClientCommandDeliverServicer` 内存活跃流表（`client_queues` / `tenant_clients`），耗时 `< 2 ms`；Redis 在线集合维护全部采用 `pipeline(transaction=False)` 批量执行。
- **端到端安全防线**：
  - **Manifest 与下载令牌 IP 绑定**：`:27041` 仅向与终端 gRPC 注册 IP 一致的请求签发资源下载 URL，且一次性 Token 在 Redis 中记录请求方 IP，防止凭据窃取与跨网重放。
  - **可信代理白名单**：仅当直连对端属于 `_TRUSTED_PROXY_HOSTS`（`127.0.0.1`、`::1`）时才采信 `X-Real-IP` / `X-Forwarded-For`。
  - **CC 频控与 OOBE 防爆破**：内置单 IP 登录/鉴权失败封禁与全局速率保护，OOBE 配对码支持常量时间比对（`secrets.compare_digest`）与单 IP 5 次失败 60 秒冷却锁定。

---

## 5. 快速开始与 CLI 命令参考

### 5.1 安装依赖

```bash
uv sync --all-groups
```

### 5.2 CLI 管理工具 (`miniclassisland`)

```bash
# 系统服务管理
uv run miniclassisland sys daemon       # 在当前前台启动四端口核心服务
uv run miniclassisland sys init         # 交互式初始化配置文件并生成 systemd 服务单元
uv run miniclassisland sys status       # 查看后台守护进程运行状态

# 用户与超管管理
uv run miniclassisland user list        # 列出所有注册用户
uv run miniclassisland user create      # 创建新用户或超级管理员
uv run miniclassisland user passwd      # 重置指定用户密码

# 租户账户与终端管理
uv run miniclassisland account list     # 列出所有租户账户
uv run miniclassisland client list      # 查看已注册终端设备列表

# CI / 开发者工具
uv run miniclassisland ci grpc generate # 重新编译 Protobuf (.proto) 至 app/Protobuf/
uv run miniclassisland ci test          # 运行 pytest 测试套件
```

### 5.3 运行测试与质量检查

测试套件自动使用独立的 `miniclassisland_test` 数据库（定义于 [`tests/conftest.py`](tests/conftest.py)），不会污染生产或本地运行数据库：

```bash
# 1. 运行全量单元测试并校验 100% 覆盖率
uv run pytest --cov=app --cov-report=term-missing

# 2. 代码格式、Lint 与静态类型检查
uv run black --check app tests
uv run ruff check app tests
uv run pyright
```

---

## 6. 贡献指南与开源协议

- 参与开发前请阅读 [`CONTRIBUTING.md`](CONTRIBUTING.md)。
- 所有 Git Commit 必须使用 SSH 或 GPG 密钥签名（`git commit -S`）。
- 本项目基于 [GNU General Public License v3.0 (GPL-3.0)](LICENSE) 开源。
