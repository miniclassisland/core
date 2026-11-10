# MINI ClassIsland Backend Core 贡献指南 (`CONTRIBUTING.md`)

欢迎为 **MINI ClassIsland Backend Core (`miniclassisland/core`)** 贡献代码！为确保集控核心在千级租户、万级终端连接下的稳定性与安全性，所有贡献者必须严格遵守以下开发与验证规范。

---

## 1. 开发环境准备

- **Python 版本**：Python `>= 3.11`（推荐使用 Python `3.12`）。
- **包管理器**：[uv](https://docs.astral.sh/uv/)。
- **基础设施依赖**：
  - PostgreSQL `14+`（需确保本地存在测试数据库 `miniclassisland_test`，`conftest.py` 会在测试时自动管理表结构）。
  - Redis `6+`（监听 `localhost:6379`）。

```bash
cd core
uv sync --all-groups
```

---

## 2. 架构与编码准则

1. **多租户隔离（Row-Level Multi-Tenancy）**：
   - 所有租户配置模型（`ClassPlan`、`TimeLayout`、`Subjects`、`DefaultSettings`、`Policy`、`Components`、`Credentials`、`ClientProfile`）均使用 `(account_id, name)` 或 `(account_id, client_id)` 复合主键。
   - 任何数据库查询与更新必须显式包含 `account_id` 条件，严禁跨租户读写。
2. **异步非阻塞原则**：
   - 四个服务端口（`:27041`、`:27042`、`:27043`、`:27044`）共享 asyncio 事件循环。
   - 严禁在协程内直接调用阻塞式 CPU 密集型或同步 I/O 操作（例如 OpenPGP RSA 解密或 Argon2id 哈希计算必须通过 `asyncio.to_thread` 卸载到线程池）。
   - Redis 批量读写优先使用 `rd.pipeline(transaction=False)`，高频读路径优先结合进程内短 TTL L1 缓存。
3. **Protobuf 生成文件规范**：
   - `app/Protobuf/` 目录下的文件由 `uv run miniclassisland ci grpc generate` 自动生成并修复相对导入，请勿手动编辑生成产物。
4. **测试数据库安全隔离**：
   - [`tests/conftest.py`](tests/conftest.py) 强制将 `DATABASE_URL` 指向 `miniclassisland_test`。编写测试时严禁硬编码生产库连接串。

---

## 3. 强制质量门禁（Quality Gates）

在提交代码前，必须在 `core/` 目录下顺序执行以下四项检查，且**全部零错误通过**：

```bash
# 1. 单元测试与覆盖率门禁（必须达到 100% 覆盖率，0 Miss）
uv run pytest --cov=app --cov-report=term-missing

# 2. Black 代码格式化检查（目标版本 py312）
uv run black --check app tests

# 3. Ruff 静态代码分析
uv run ruff check app tests

# 4. Pyright 静态类型检查
uv run pyright
```

> [!IMPORTANT]
> 本仓库对业务代码实行严格的 **100% 行覆盖率** 要求（`app/Protobuf/*` 与 `app/main.py` 除外）。新增任何路由、gRPC 分支或异常处理逻辑时，必须在 `tests/` 对应目录下补充单元测试覆盖所有分支。

---

## 4. 强制提交签名 (`git commit -S`) 与提交规范

1. **SSH / GPG 签名**：
   所有 Commit 必须使用已在 GitHub 绑定的 SSH 或 GPG 密钥进行签名：
   ```bash
   git config gpg.format ssh
   git config user.signingkey "~/.ssh/id_ed25519.pub"
   git config commit.gpgsign true
   ```
2. **Conventional Commits 格式**：
   ```bash
   git commit -S -m "perf(grpc): add L1 session cache and pipeline online state updates"
   ```
   允许的 `type`：`feat`、`fix`、`perf`、`sec`、`docs`、`test`、`refactor`、`chore`。
