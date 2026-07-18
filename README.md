# MINIClassIsland Backend Core

> ClassIsland Management Server (MINIClassIsland 集控服务端) — Python 实现  
> 基于 [Cyrene_MSP 协议 v2.0.0.0](https://github.com/ClassIsland/ClassIsland/tree/master/doc/Design/Cyrene_MSP)

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-green)](LICENSE)

---

## 概述

MINIClassIsland Backend Core 是 [ClassIsland](https://github.com/ClassIsland/ClassIsland) 的集中管理后端，为教育场景提供多租户校园终端设备管理能力。它通过 HTTP API 与 gRPC 双通道同时服务终端和管理后台，实现课表分发、远程指令下发、配置同步、审计日志等核心功能。

## 技术栈

| 组件 | 技术 |
|------|------|
| HTTP API | [FastAPI](https://fastapi.tiangolo.com/) + [Uvicorn](https://www.uvicorn.org/) |
| 实时通信 | [gRPC](https://grpc.io/) (grpcio) |
| 数据库 | [PostgreSQL](https://www.postgresql.org/) (psycopg + SQLAlchemy 2.0) |
| 缓存 / 会话 | [Redis](https://redis.io/) (hiredis) |
| 协议定义 | [Protocol Buffers 3](https://protobuf.dev/) |
| 包管理 | [uv](https://docs.astral.sh/uv/) |
| 密钥管理 | [PGPy](https://pgpy.readthedocs.io/) (OpenPGP) |

## 核心功能

### 多租户架构

- 基于子域名的行级租户隔离（如 `school-a.miniclassisland.com`）
- 每个租户拥有独立数据空间，通过 `tenant_id` 关联所有业务数据
- 支持租户级 API Key 分发与轮换
- Redis 缓存租户解析结果，降低数据库压力

### 四端口服务

| 端口 | 服务 | 说明 |
|------|------|------|
| `:27041` | **Client API** | 面向 ClassIsland 客户端 — 提供配置清单（Manifest）和资源文件下载 |
| `:27042` | **Management API** | 商户/普通用户管理 — 认证、账户操作、资源管理、客户端控制 |
| `:27043` | **Admin API** | 超管后台 — 全局用户/账户管理、系统配置设置 |
| `:27044` | **gRPC** | Cyrene_MSP 协议 — 客户端注册、命令推送、配置上传、审计等 |

### 上游 Cyrene_MSP 协议兼容性

| 服务 | 状态 | 说明 |
|------|------|------|
| `ClientRegister` | ✅ 已实现 | 客户端注册 + PGP 密钥交换 |
| `Handshake` | ✅ 已实现 | 双向握手认证 + 会话建立 |
| `ClientCommandDeliver` | ✅ 已实现 | 双向流式命令推送（Ping/Pong 心跳） |
| `ConfigUpload` | ✅ 已实现 | 客户端配置上传到服务端 |
| `Audit` | ✅ 已实现 | 审计事件上报与持久化 |

## 快速开始

### 先决条件

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) 包管理器
- PostgreSQL
- Redis

### 安装与运行

```bash
# 1. 安装依赖
uv sync --all-groups

# 2. 编译协议
uv run miniclassisland ci grpc generate

# 3. 运行服务
uv run miniclassisland sys daemon
```

> 💡 系统提供 `miniclassisland` 命令行工具，同时保留 `cims` 作为别名使用。
