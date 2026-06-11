# sca-cli 运维手册

> 版本：v1.0
> 适用对象：运维工程师 / 安全运营 / 平台管理员
> 最后更新：2026-06-11
> 核心主题：特征库同步维护、更新策略、故障恢复、监控告警

---

## 目录

1. [概述](#1-概述)
2. [数据源架构](#2-数据源架构)
3. [同步操作指南](#3-同步操作指南)
4. [定时同步策略](#4-定时同步策略)
5. [离线环境维护](#5-离线环境维护)
6. [故障处理手册](#6-故障处理手册)
7. [监控与告警](#7-监控与告警)
8. [数据目录管理](#8-数据目录管理)
9. [版本升级指南](#9-版本升级指南)

---

## 1. 概述

### 1.1 什么是特征库

sca-cli 的「特征库」指本地 SQLite 数据库中存储的漏洞数据、许可证数据和规则数据。所有扫描依赖这些本地数据完成，**不依赖外部 API 调用**。

### 1.2 为什么需要维护

| 原因 | 说明 |
|------|------|
| 数据时效性 | 漏洞库每天都有新增/更新，过时数据导致漏报 |
| 磁盘占用 | 数据库 + 缓存约 2 GB，需关注磁盘水位 |
| 运行稳定性 | 同步中断可能导致数据库锁定，影响扫描任务 |
| 安全更新 | 内置工具（Grype/Syft）版本更新需关注 |

### 1.3 总体架构

```
外部数据源                          sca-cli 本地
────────────                       ────────────
OSV (Google) ──HTTP zip──→   cache/osv-*.zip ──→ SQLite DB
GHSA (GitHub) ──git pull──→   cache/github-advisory-db ──→ SQLite DB
SPDX (Linux Foundation) ──→   cache/spdx-licenses.json ──→ SQLite DB
AIG (Tencent) ──git clone→   rules/ai-infra/ (文件系统)
Grype DB (Anchore) ──CLI──→   grype 自带数据库
```

---

## 2. 数据源架构

### 2.1 数据源总览

| 数据源 | 类型 | 内容 | 记录数 | 存储方式 | 同步耗时 |
|-------|------|------|:------:|---------|:--------:|
| OSV | 漏洞库 | PyPI + npm 生态漏洞 | ~240,000 | SQLite 表 + zip 缓存 | 30-60s |
| GHSA | 漏洞库 | GitHub Advisory 全量 | ~118,000 | SQLite 表 + git 仓库 | 2-3 分钟 |
| Grype DB | 漏洞库 | Grype 运行时数据库 | N/A | Grype 自带 | ~30s |
| SPDX | 许可证库 | 标准许可证 727 条 | 727 | SQLite 表 + JSON 缓存 | <1s |
| AIG | 规则库 | AI Infra 规则 ~1,500 条 | ~1,500 | 文件系统 rules/ | ~10s |
| 内置规则 | 规则库 | 24+ 条内置 YAML 规则 | 24+ | 打包在 CLI 中 | 无 |

### 2.2 OSV 漏洞库

**来源：** [Google OSV](https://osv.dev/) — Open Source Vulnerabilities

**内容：** PyPI 和 npm 两个生态的完整 CVE 数据

**数据结构：**
```
每条记录包含：
- primary_id: CVE-ID 或 GHSA-ID
- title: 漏洞摘要
- description: 详细描述
- severity: CVSS 评分的严重等级映射
- published_at / modified_at: 时间戳
- affected: 影响包列表（生态、包名、版本范围、修复版本）
- aliases: 别名（CVE ↔ GHSA 映射）
- references: 引用链接
```

**缓存文件：**
- `~/.sca-cli/cache/osv-pypi.zip` — ~24 MB（20,417 条）
- `~/.sca-cli/cache/osv-npm.zip` — ~200 MB（220,514 条）

**更新方式：** 重新下载全量 zip 文件，解压后 batch 插入 SQLite。

### 2.3 GHSA 漏洞库

**来源：** [GitHub Advisory Database](https://github.com/github/advisory-database)

**内容：** GitHub 全平台安全公告（含 OSV 已有 CVE + GitHub 独有 GHSA）

**数据结构：**
```
每条记录包含：
- primary_id: GHSA-xxxx-xxxx-xxxx
- summary: 漏洞概要
- details: 详细描述
- severity: GitHub 预评文本等级（CRITICAL/HIGH/MODERATE/LOW）
- published_at / updated_at: 时间戳
- affected: 影响包列表
- identifiers: CVE 等别名
- database_specific: GitHub 自有字段（cwe_ids, severity 等）
```

**缓存仓库：** `~/.sca-cli/cache/github-advisory-database/` — ~800 MB

**目录结构：**
```
advisories/
├── github-reviewed/          # 2023 年及之前（单层目录）
│   └── YYYY/GHSA-xxxx.json
└── unreviewed/               # 2023 年后（年月目录）
    └── YYYY/MM/GHSA-xxxx/GHSA-xxxx.json
```

**更新方式：** `git pull` 增量拉取，每次只下载变更部分。

### 2.4 Grype DB

**来源：** [Anchore Grype](https://github.com/anchore/grype)

**内容：** 综合漏洞数据库（集成 NVD、RedHat、Ubuntu、Alpine 等官方源）

**更新方式：** 执行 `grype db update` 命令。

**使用方式：** 不直接导入 SQLite，而是在 `sca-cli scan --vuln` 时通过 Grype 调用。

### 2.5 SPDX 许可证库

**来源：** [SPDX License List](https://spdx.org/licenses/)

**内容：** SPDX 标准许可证 727 条

**缓存文件：** `~/.sca-cli/cache/spdx-licenses.json` — ~330 KB

**更新方式：** HTTP 下载 JSON 文件，全部替换。

### 2.6 AIG 规则库

**来源：** [Tencent AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)

**内容：** AI 基础设施安全规则，分三类：
- `data-fingerprints/` — AI 框架版本指纹（~500 条）
- `data-vuln/` — AI 组件已知漏洞（~500 条）
- `data-mcp/` — MCP 协议安全检测（~500 条）

**存储位置：** `~/.sca-cli/rules/ai-infra/`

**更新方式：** Git clone / pull 后复制到规则目录。

---

## 3. 同步操作指南

### 3.1 首次全量同步

```bash
# 1. 初始化
sca-cli init --home ~/.sca-cli

# 2. 验证环境
sca-cli doctor --home ~/.sca-cli

# 3. 全量同步所有数据源
sca-cli sync --all --home ~/.sca-cli

# 4. 检查数据库状态
sca-cli db status --home ~/.sca-cli
```

**预期耗时：** 约 4-5 分钟（取决于网络和磁盘性能）

| 步骤 | 耗时 | 说明 |
|------|:----:|------|
| SPDX | <1s | HTTP JSON，一次请求 |
| OSV | 30-60s | 2 个 zip 文件下载 + 解压 + batch 插入 |
| GHSA | 2-3 分钟 | Git clone（首次）或 pull + 多线程解析 118k JSON |
| AIG | ~10s | Git clone + 复制 1,500+ 规则文件 |
| Grype DB | ~30s | 执行 grype db update |

### 3.2 增量同步

```bash
# 更新所有已配置数据源
sca-cli sync --all --home ~/.sca-cli

# 仅更新特定数据源
sca-cli sync --source osv --home ~/.sca-cli
sca-cli sync --source ghsa --home ~/.sca-cli
```

增量同步的判断逻辑：
- **OSV**：检查本地 zip 缓存 → 直接使用缓存 zip 重新导入（OSV 是全量 zip，没有增量格式）
- **GHSA**：`git pull` 增量拉取变更
- **SPDX**：重新下载 JSON（全量替换）
- **AIG**：`git pull` 增量拉取
- **Grype DB**：`grype db update` 自动增量

### 3.3 强制全量刷新

```bash
sca-cli sync --source osv --full --home ~/.sca-cli
sca-cli sync --source ghsa --full --home ~/.sca-cli
```

`--full` 参数会跳过源状态检查，强制重新导入所有数据。

### 3.4 查看同步状态

```bash
sca-cli db status --home ~/.sca-cli
```

输出示例：
```
Source    │ Status   │ Records
──────────┼──────────┼─────────
osv       │ ok       │ 240,931
ghsa      │ ok       │ 118,497
spdx      │ ok       │ 727
aig       │ ok       │ 1,554
grype-db  │ ok       │ 1
nvd       │ never    │ 0
```

---

## 4. 定时同步策略

### 4.1 推荐策略

| 数据源 | 同步频率 | 建议时间 |
|-------|---------|---------|
| OSV | 每日一次 | 凌晨 2-4 点 |
| GHSA | 每日一次 | 凌晨 2-4 点 |
| Grype DB | 每次扫描前 | 按需 |
| SPDX | 每月一次 | 月初 |
| AIG | 每月一次 | 月初 |

### 4.2 Cron 配置

**Linux/macOS：**
```bash
crontab -e

# 每天凌晨 2 点同步漏洞库
0 2 * * * cd /opt/sca-cli && sca-cli sync --all --home /opt/sca-cli-data >> /var/log/sca-cli-sync.log 2>&1

# 每周一凌晨 3 点全量刷新（可选）
0 3 * * 1 cd /opt/sca-cli && sca-cli sync --source osv --full --home /opt/sca-cli-data >> /var/log/sca-cli-sync.log 2>&1
```

**Windows 计划任务：**
```powershell
# PowerShell 管理员模式创建每日同步任务
$action = New-ScheduledTaskAction -Execute "sca-cli" -Argument "sync --all --home C:\sca-cli-data"
$trigger = New-ScheduledTaskTrigger -Daily -At 02:00AM
Register-ScheduledTask -TaskName "sca-cli-sync" -Action $action -Trigger $trigger -RunLevel Highest
```

### 4.3 同步日志

建议将同步输出重定向到日志文件便于排查：

```bash
sca-cli sync --all --home ~/.sca-cli >> /var/log/sca-cli-sync-$(date +%Y%m%d).log 2>&1
```

---

## 5. 离线环境维护

### 5.1 场景说明

对于政府、金融、关键基础设施等需要完全隔离的网络环境，sca-cli 支持离线更新。

### 5.2 联网环境导出

在有外网的机器上：

```bash
# 1. 全量同步
sca-cli sync --all --home ~/.sca-cli

# 2. 导出为离线包
sca-cli sync --offline-export ~/sca-cli-bundle-20260611.zip --home ~/.sca-cli
```

离线包包含：
- SQLite 数据库文件（漏洞 + 许可证）
- 配置文件
- rules/ 目录下的所有规则

### 5.3 隔离环境导入

将离线包拷贝到隔离机器：

```bash
# 导入离线包
sca-cli sync --offline-import /path/to/sca-cli-bundle-20260611.zip --home /opt/sca-cli

# 重新初始化数据库
sca-cli init --home /opt/sca-cli

# 验证
sca-cli doctor --home /opt/sca-cli
sca-cli db status --home /opt/sca-cli
```

> 注意：离线导入会备份目标目录下已有的数据库（添加 `.bak` 后缀）。

### 5.4 离线更新频率

| 环境类型 | 建议更新频率 | 说明 |
|---------|:----------:|------|
| 低敏环境 | 每周一次 | 可通过安全 U 盘传递 |
| 高敏环境 | 每月一次 | 需经过审批流程 |
| 核心系统 | 每季度一次 | 需经过完整变更流程 |

---

## 6. 故障处理手册

### 6.1 数据库锁定（database is locked）

**现象：** sync 或 scan 命令报 `database is locked` 或 `OperationalError: database is locked`。

**原因：** SQLite 事务未正常提交/回滚。常见场景：
- sync 过程中 Ctrl+C 中断
- 进程被 OOM Killer 或 timeout 强制杀死
- 多个进程同时写入同一数据库

**标准恢复流程：**

```bash
# 第一步：杀残留进程
taskkill /F /IM python.exe  # Windows
pkill -9 python              # Linux/macOS

# 第二步：清理 journal 文件
rm -f ~/.sca-cli/sca-cli.db-journal

# 第三步：尝试打开
sca-cli db status --home ~/.sca-cli

# 如果仍然报错，说明数据文件已损坏 → 走重建流程
```

**数据库重建流程（推荐路径）：**

```bash
# 1. 初始化新目录
sca-cli init --home ~/.sca-cli-v2

# 2. 拷贝缓存文件（避免重新下载）
cp ~/.sca-cli/cache/osv-pypi.zip ~/.sca-cli-v2/cache/
cp ~/.sca-cli/cache/osv-npm.zip ~/.sca-cli-v2/cache/
cp ~/.sca-cli/cache/spdx-licenses.json ~/.sca-cli-v2/cache/
cp ~/.sca-cli/config.yaml ~/.sca-cli-v2/

# 3. GHSA 仓库用 git 拉取（不要 cp，文件太多太慢）
cd ~/.sca-cli-v2/cache
git clone https://github.com/github/advisory-database.git

# 4. 重同步
sca-cli sync --all --home ~/.sca-cli-v2
```

**核心原则：** 数据库损坏不可逆，放弃修复、建新库、重同步是最快的路径。不要尝试 `PRAGMA integrity_check` 或 `.recover`——成功率极低。

### 6.2 同步超时

#### OSV 超时

**现象：** `sca-cli sync --source osv` 长时间无响应。

**原因：** 原代码逐条 INSERT（240k 条 × ~10 次 SQL = 240 万次操作），单个事务过大。

**已在 v2.0 中优化的方案：** 使用 batch `executemany`，每 500 条一批提交。优化后 OSV 同步从 >10 分钟降至 30-60 秒。

#### GHSA 超时

**现象：** `sca-cli sync --source ghsa` 长时间卡在 "Collecting GHSA advisory files..."。

**原因：** 单线程遍历 118k 个 JSON 文件 + JSON 解析。

**已在 v2.0 中优化的方案：** 使用 `os.walk` 替代 `pathlib.rglob`，使用 8 线程并行读取解析。优化后从 600s 超时降至约 2-3 分钟。

### 6.3 GHSA 0 条记录

**现象：** sync 显示 `ok` 但 0 条记录。

**原因：** 代码只搜索了 `advisories/github-reviewed/` 目录，但新版 GHSA 仓库的 JSON 文件在 `advisories/unreviewed/YYYY/MM/GHSA-xxxx/` 下。

**解决：** 确认 `_sync_ghsa` 函数同时搜索 `github-reviewed` 和 `unreviewed` 两个目录。

### 6.4 severity 解析错误

**现象：** `'list' object has no attribute 'lower'`

**原因：** GHSA 的 `severity` 字段是列表格式 `[{"type": "CVSS_V3", "score": "CVSS:3.1/...", ...}]`，代码调了 `.lower()`。

**解决：** 使用 `database_specific.severity` 获取 GitHub 预计算文本等级。

### 6.5 磁盘空间不足

**现象：** sync 失败，报磁盘空间不足。

**数据库和缓存大小参考：**

| 组件 | 大小 |
|------|:----:|
| SQLite 数据库（含 OSV + GHSA） | ~1.3 GB |
| OSV zip 缓存（pypi + npm） | ~224 MB |
| GHSA git 仓库 | ~800 MB |
| SPDX 缓存 | ~330 KB |
| AIG 规则 | ~5 MB |
| **总计** | **~2.3 GB** |

**建议：**
- 确保数据目录所在分区至少有 5 GB 空闲空间
- 定期清理 `reports/` 目录中的历史报告
- GHSA 仓库用 `git gc` 压缩

### 6.6 cache 拷贝太慢

**现象：** 手动 cp GHSA 目录时花费数分钟。

**原因：** GHSA 仓库有 79k 个文件、800 MB。

**解决：** 不要 `cp`，用 `git pull`：
```bash
cd ~/.sca-cli-v2/cache/github-advisory-database
git pull --ff-only
```

---

## 7. 监控与告警

### 7.1 健康检查脚本

```bash
#!/bin/bash
# sca-cli-healthcheck.sh

HOME_DIR="${1:-$HOME/.sca-cli}"
FAILED=0

echo "=== sca-cli Health Check ==="
echo "Data home: $HOME_DIR"
echo ""

# 1. 检查数据库是否存在
if [ -f "$HOME_DIR/sca-cli.db" ]; then
    SIZE=$(du -h "$HOME_DIR/sca-cli.db" | cut -f1)
    echo "[OK] Database exists: $SIZE"
else
    echo "[FAIL] Database not found"
    FAILED=1
fi

# 2. 检查 doctor
if sca-cli doctor --home "$HOME_DIR" --json 2>/dev/null | grep -q '"status":"OK"'; then
    echo "[OK] doctor check passed"
else
    echo "[WARN] doctor check failed"
fi

# 3. 检查最近同步时间
LAST_SYNC=$(sqlite3 "$HOME_DIR/sca-cli.db" \
  "SELECT MAX(finished_at) FROM sync_runs WHERE status='ok'" 2>/dev/null)
echo "[OK] Last successful sync: ${LAST_SYNC:-never}"

# 4. 检查磁盘
AVAILABLE=$(df -h "$HOME_DIR" | tail -1 | awk '{print $4}')
echo "[OK] Disk available: $AVAILABLE"

exit $FAILED
```

### 7.2 Prometheus 指标

可通过 `--json` 输出对接 Prometheus Pushgateway：

```bash
# 收集指标
sca-cli db status --home ~/.sca-cli --json > /tmp/sca-cli-metrics.json

# 提取关键指标
jq -r '.sources[] | "sca_cli_sync_records{source=\"\(.name)\"} \(.record_count)"' \
  /tmp/sca-cli-metrics.json | curl --data-binary @- http://pushgateway:9091/metrics/job/sca-cli
```

### 7.3 告警规则

| 告警条件 | 严重性 | 处理 |
|---------|:------:|------|
| 最近 24 小时无成功同步 | Warning | 检查 cron 任务和网络 |
| 数据库小于 100 MB | Warning | 数据可能丢失，检查同步状态 |
| doctor 检查失败 | Critical | 检查 Python 环境和外部工具 |
| 磁盘使用率 > 85% | Warning | 清理历史报告或扩容 |
| 同步连续失败 3 次 | Critical | 检查数据源可用性 |

---

## 8. 数据目录管理

### 8.1 多实例部署

支持多套数据目录隔离部署：

```bash
# 生产环境
sca-cli --home /opt/sca-cli-prod

# 测试环境
sca-cli --home /opt/sca-cli-test

# 开发环境
sca-cli --home ~/.sca-cli-dev
```

### 8.2 报告清理

```bash
# 查看报告目录大小
du -sh ~/.sca-cli/reports/

# 清理 30 天前的报告
find ~/.sca-cli/reports/ -type f -mtime +30 -delete

# 保留最近 10 份报告
ls -t ~/.sca-cli/reports/ | tail -n +11 | xargs -I {} rm -rf ~/.sca-cli/reports/{}
```

### 8.3 缓存清理

```bash
# 查看缓存大小
du -sh ~/.sca-cli/cache/

# 仅清除 OSV zip 缓存（下次 sync 会重新下载）
rm ~/.sca-cli/cache/osv-pypi.zip ~/.sca-cli/cache/osv-npm.zip

# 重新克隆 GHSA 仓库（如果损坏）
rm -rf ~/.sca-cli/cache/github-advisory-database
sca-cli sync --source ghsa --home ~/.sca-cli  # 自动重新 clone

# 清除所有缓存（下次 sync 全部重新下载）
rm -rf ~/.sca-cli/cache/*
```

### 8.4 数据库迁移

将数据目录迁移到新磁盘：

```bash
# 停止所有 sca-cli 进程
# 拷贝整个目录
cp -a ~/.sca-cli /new/disk/sca-cli-data

# 验证
sca-cli doctor --home /new/disk/sca-cli-data

# 更新配置或 --home 参数
```

---

## 9. 版本升级指南

### 9.1 CLI 升级

```bash
# pip 安装的
pip install --upgrade sca-cli

# 源码运行的
cd /opt/sca-cli
git pull
pip install -e .
```

### 9.2 数据库迁移

sca-cli 使用 SQLite 自带的 schema 版本管理。升级后首次运行会自动执行迁移。

```bash
# 升级前建议备份
cp ~/.sca-cli/sca-cli.db ~/.sca-cli/sca-cli.db.bak

# 升级后首次运行会自动迁移
sca-cli doctor --home ~/.sca-cli
```

### 9.3 回滚

```bash
# 停止当前进程
# 恢复备份的数据库
cp ~/.sca-cli/sca-cli.db.bak ~/.sca-cli/sca-cli.db

# 恢复上一版本 CLI
pip install sca-cli==1.0.0
```

### 9.4 更新检查清单

| 检查项 | 操作 |
|--------|------|
| 备份数据库 | `cp sca-cli.db sca-cli.db.bak` |
| 备份规则 | `cp -r rules rules.bak` |
| 升级 CLI | `pip install --upgrade sca-cli` |
| 重新同步 | `sca-cli sync --all` |
| 验证 | `sca-cli doctor && sca-cli db status` |
| 试扫描 | `sca-cli scan ./test-target` |
| 清理备份 | 确认运行正常后删除备份 |

---

> **相关文档：**
> - [用户手册](sca-cli_USER_GUIDE.md) — 命令详解、扫描使用
> - [开发规范](sca-cli_SPEC_v2.md) — 项目架构与开发指引
> - [实现说明](sca-cli_IMPLEMENTATION.md) — 当前实现状态与待办
