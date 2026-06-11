# sca-cli 用户使用手册

> 版本：v2.0
> 适用对象：安全工程师 / 开发工程师 / DevOps / AI Agent 平台运营
> 最后更新：2026-06-11

---

## 目录

1. [快速开始](#1-快速开始)
2. [安装与配置](#2-安装与配置)
3. [命令参考](#3-命令参考)
4. [扫描目标与输入格式](#4-扫描目标与输入格式)
5. [扫描报告解读](#5-扫描报告解读)
6. [威胁情报报告](#6-威胁情报报告)
7. [规则管理](#7-规则管理)
8. [CI/CD 集成](#8-cicd-集成)
9. [FAQ](#9-faq)

---

## 1. 快速开始

### 1.1 一句话上手

```bash
# 初始化
sca-cli init --home ~/.sca-cli

# 同步漏洞库（首次必须）
sca-cli sync --all --home ~/.sca-cli

# 扫描一个 Skill 包
sca-cli scan ./my-skill.zip --vuln --report --home ~/.sca-cli

# 打开报告
open ~/.sca-cli/reports/latest/scan_report.html
```

### 1.2 前置依赖

| 工具 | 用途 | 安装方式 |
|------|------|---------|
| Python 3.11+ | 运行环境 | python.org 或包管理器 |
| Syft（可选） | SBOM 生成 | `winget install anchore.syft` 或官网 |
| Grype（可选） | 通用漏洞扫描 | `winget install anchore.grype` 或官网 |
| pip-audit（可选） | Python 专项漏洞 | `pip install pip-audit` |
| npm（可选） | JS 专项漏洞 | Node.js 自带或 `nvm install` |
| Git（可选） | GHSA/AIG 同步 | git-scm.com |

> 除 Python 外均为可选。缺失的工具不影响主流程，scan 会自动跳过并记录 warning。

### 1.3 环境验证

```bash
sca-cli doctor --home ~/.sca-cli
```

输出示例：
```
Check     │ Value                          │ Status
─────────┼────────────────────────────────┼────────
python   │ 3.13.2                         │ OK
sqlite   │ 3.45.3                         │ OK
Syft     │ C:\Tools\syft.exe              │ OK
Grype    │ C:\Tools\grype.exe             │ OK
pip-audit│ pip-audit 2.10.1               │ OK
npm      │ C:\Program Files\nodejs\npm.cmd│ OK
git      │ C:\Program Files\Git\bin\git   │ OK
data-home│ C:\Users\xxx\.sca-cli          │ OK
database │ C:\Users\xxx\.sca-cli\sca-cli.db│ OK
rules-dir│ C:\Users\xxx\.sca-cli\rules    │ OK
```

---

## 2. 安装与配置

### 2.1 安装方式

**方式一：pip 安装**
```bash
pip install sca-cli
```

**方式二：源码运行**
```bash
git clone https://github.com/bigsinger/sca-cli.git
cd sca-cli
pip install -e .
```

**方式三：直接运行（不安装）**
```bash
git clone https://github.com/bigsinger/sca-cli.git
cd sca-cli
python -m sca_cli.main scan ./target
```

### 2.2 数据目录结构

默认数据目录 `./data/`（项目根目录下，与 `src/` 同级），可通过 `--home` 参数或 `SCA_CLI_HOME` 环境变量覆盖：

```
data/                         # 数据根目录（与 src/ 同级）
├── sca-cli.db                # SQLite 主数据库（漏洞库 + 许可证库）
├── config.yaml               # 用户配置文件
├── cache/
│   ├── osv-pypi.zip          # OSV PyPI 缓存（~24 MB）
│   ├── osv-npm.zip           # OSV npm 缓存（~200 MB）
│   ├── spdx-licenses.json    # SPDX 许可证缓存
│   └── github-advisory-database/  # GHSA Git 仓库（~800 MB）
├── rules/
│   └── ai-infra/             # AIG 导入规则
├── reports/                  # 扫描报告输出目录
├── downloads/                # URL 下载的临时文件
├── workspaces/               # 解压/克隆的工作区
├── sbom/                     # SBOM 输出目录
└── logs/                     # 运行日志
```

### 2.3 配置文件

`config.yaml` 示例：

```yaml
sync:
  enabled_sources:
    - osv
    - spdx
  timeout_seconds: 120
  proxy: null

external_tools:
  syft: syft
  grype: grype
  pip_audit: pip-audit
  npm: npm
  git: git

scan:
  default_scanner: auto
  max_download_size_mb: 500
  fail_on: none
  report_formats:
    - html
    - md
    - json
```

---

## 3. 命令参考

### 3.1 `sca-cli init`

初始化数据目录和数据库。

```bash
sca-cli init                     # 默认 ~/.sca-cli
sca-cli init --home /opt/sca-cli # 自定义路径
sca-cli init --force             # 重新初始化（清空已有数据）
```

### 3.2 `sca-cli doctor`

检查运行环境完整性。

```bash
sca-cli doctor
sca-cli doctor --home ~/.sca-cli
```

### 3.3 `sca-cli scan`

对目标执行供应链安全扫描。

**基本用法：**
```bash
# 最小扫描（规则 + SBOM）
sca-cli scan ./target

# 全量扫描（漏洞 + 规则 + SBOM + 报告）
sca-cli scan ./target --vuln --report

# 全量扫描 + 许可证检测 + 所有扫描器
sca-cli scan ./target --vuln --rules --license --report --scanner all

# 指定报告格式
sca-cli scan ./target --vuln --report --format html,md,json

# 指定输出目录
sca-cli scan ./target --report --output /tmp/reports

# CI/CD 门禁：高风险阻断
sca-cli scan ./target --vuln --fail-on high --json
```

**参数详解：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `TARGET` | 必填 | 扫描目标（目录/zip/Git URL/HTTP URL） |
| `--name` | 自动 | 项目名称 |
| `--type` | auto | 项目类型：auto/python/javascript/mcp/plugin |
| `--skill-mode` | auto | Skill 模式：agent/mcp/plugin/auto |
| `--sbom` | 开启 | 生成 CycloneDX SBOM |
| `--no-sbom` | — | 跳过 SBOM 生成 |
| `--vuln` | 关闭 | 启用漏洞扫描 |
| `--rules` | 开启 | 启用规则扫描 |
| `--no-rules` | — | 跳过规则扫描 |
| `--license` | 关闭 | 启用许可证扫描 |
| `--report` | 关闭 | 生成扫描报告 |
| `--format` | html,md,json | 报告格式 |
| `--scanner` | auto | 扫描引擎：auto/all/engine1,engine2 |
| `--fail-on` | none | 阻断阈值：critical/high/medium/low/none |
| `--offline` | 关闭 | 离线模式（跳过网络扫描器） |
| `--home` | ~/.sca-cli | 数据目录路径 |
| `--json` | 关闭 | 输出 JSON 格式结果 |

### 3.4 `sca-cli sync`

同步漏洞库和规则库。

```bash
# 全量同步所有数据源
sca-cli sync --all --home ~/.sca-cli

# 同步指定数据源
sca-cli sync --source osv --home ~/.sca-cli
sca-cli sync --source ghsa --home ~/.sca-cli
sca-cli sync --source spdx --home ~/.sca-cli
sca-cli sync --source aig --home ~/.sca-cli
sca-cli sync --source grype-db --home ~/.sca-cli

# 强制全量刷新
sca-cli sync --source osv --full --home ~/.sca-cli

# 离线导出/导入
sca-cli sync --offline-export ~/sca-bundle.zip --home ~/.sca-cli
sca-cli sync --offline-import ~/sca-bundle.zip --home /opt/isolated/sca-cli
```

### 3.5 `sca-cli intel report`

生成威胁情报报告。

```bash
# 默认 24 小时
sca-cli intel report --home ~/.sca-cli

# 自定义时间范围
sca-cli intel report --range 7d --home ~/.sca-cli
sca-cli intel report --from 2026-06-01 --to 2026-06-11 --home ~/.sca-cli

# 按生态筛选
sca-cli intel report --range 24h --ecosystem pypi --home ~/.sca-cli

# 按严重等级筛选
sca-cli intel report --range 24h --severity critical,high --home ~/.sca-cli

# 聚焦 AI Agent 生态
sca-cli intel report --range 24h --focus agent --home ~/.sca-cli
```

### 3.6 `sca-cli rules`

规则列表与验证。

```bash
# 列出所有规则
sca-cli rules list --home ~/.sca-cli

# 验证规则文件语法
sca-cli rules validate --home ~/.sca-cli
```

### 3.7 `sca-cli db`

数据库状态与维护。

```bash
# 查看数据库状态
sca-cli db status --home ~/.sca-cli

# 重置数据库（清空所有数据）
sca-cli db reset --home ~/.sca-cli
```

---

## 4. 扫描目标与输入格式

sca-cli 支持多种输入类型：

| 输入类型 | 示例 | 说明 |
|---------|------|------|
| 本地目录 | `./my-skill/` | 直接扫描目录 |
| 本地压缩包 | `./my-skill.zip` | 支持 .zip / .tar / .tgz / .tar.gz |
| Git URL | `https://github.com/user/repo.git` | 自动 clone 后扫描 |
| 归档 URL | `https://example.com/skill.zip` | 自动下载后扫描 |

**URL 安全限制：**
- 最大下载大小：500 MB（可配置）
- 下载到隔离目录，随机文件名
- 解压时防 Zip Slip 路径穿越
- 不执行被扫描项目的任何代码

---

## 5. 扫描报告解读

### 5.1 报告结构

扫描报告包含 15 个标准化章节：

| 章节 | 内容 |
|------|------|
| 封面 | 项目名、扫描时间、工具版本 |
| 扫描摘要 | 组件数、发现数、风险等级 |
| 风险评级 | Critical / High / Medium / Low 分布 |
| Skill 类型识别 | 识别为 Python/JS/MCP/Plugin 等 |
| 组件与 SBOM | CycloneDX 物料清单 |
| 漏洞扫描结果 | 依赖漏洞详情（引擎、CVE、严重性） |
| Python/JS 专项 | pip-audit / npm audit 结果 |
| 元数据风险 | Tool description 投毒、MCP 参数越权 |
| 安装脚本风险 | setup.py / package.json scripts 恶意行为 |
| 高危 API | eval/exec/subprocess 等调用 |
| 许可证风险 | 不合规许可证检测 |
| 威胁情报关联 | 关联到本地漏洞库 |
| 修复建议 | 每个 finding 的修复方案 |
| 组件清单 | 完整依赖列表 |
| 原始扫描器信息 | 各引擎原始输出 |

### 5.2 风险等级说明

**Agent Skill 加权评分体系：**

| 风险条件 | 加权分 |
|---------|:------:|
| MCP tool 任意命令参数 | +25 |
| 安装脚本执行 shell | +20 |
| 读取环境变量 + 外联 | +20 |
| tool description 指令注入 | +15 |
| npm/pypi 高危漏洞 | +10 |
| 无 lockfile | +8 |
| 未知许可证 | +5 |
| 多引擎同时命中 | +5 |

**等级划分：** 0-30 Low / 31-60 Medium / 61-85 High / 86+ Critical

### 5.3 Finding 字段说明

每个 finding 包含：

```
- id: 规则 ID 或 CVE
- title: 问题标题
- severity: critical/high/medium/low/info
- confidence: high/medium/low
- category: vuln/script/metadata/api/license
- location: 文件路径 + 行号
- description: 问题描述
- remediation: 修复建议
- source: 发现引擎（Grype/pip-audit/规则引擎等）
```

---

## 6. 威胁情报报告

威胁情报报告帮助安全团队追踪与 Agent Skill 相关的漏洞动态。

### 6.1 报告内容

- 时间范围内新增/更新的漏洞
- 按生态（PyPI / npm）分类
- 按严重等级分类
- 关联到 Agent Skill 常用组件
- 修复版本信息

### 6.2 使用场景

**每日监控：**
```bash
# 每天早上查看过去 24 小时新增漏洞
sca-cli intel report --range 24h --format html

# 仅关注高严重性
sca-cli intel report --range 24h --severity critical,high

# 仅关注 Python 生态
sca-cli intel report --range 24h --ecosystem pypi
```

**事件响应：**
```bash
# 某 CVE 曝光后，查询相关受影响组件
sca-cli intel report --range 7d --focus agent
```

---

## 7. 规则管理

### 7.1 规则层级

规则按优先级自上而下加载：

```
内置规则 → 用户本地规则（~/.sca-cli/rules/） → AIG 导入规则
```

### 7.2 编写自定义规则

规则以 YAML 格式编写。示例：

```yaml
id: CUSTOM-API-001
name: "自定义高危 API 检测"
severity: high
description: "检测使用了 os.system 的危险调用"
match:
  patterns:
    - "os\\.system\\("
  file_types:
    - ".py"
remediation: "请使用 subprocess.run() 替代 os.system()"
```

### 7.3 规则验证

```bash
sca-cli rules validate --home ~/.sca-cli
```

---

## 8. CI/CD 集成

### 8.1 GitHub Actions 示例

```yaml
name: Agent Skill Security Scan
on:
  pull_request:
    paths:
      - 'skills/**'
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install sca-cli
        run: pip install sca-cli
      - name: Sync vulnerability DB
        run: sca-cli sync --all --home ~/.sca-cli
      - name: Scan skills
        run: |
          sca-cli scan ./skills --vuln --rules --fail-on high \
            --json --home ~/.sca-cli
```

### 8.2 GitLab CI 示例

```yaml
scan:
  stage: test
  image: python:3.11
  script:
    - pip install sca-cli
    - sca-cli sync --source spdx --home ~/.sca-cli
    - sca-cli scan ./agent-skills/ --vuln --fail-on high \
        --json --home ~/.sca-cli
```

### 8.3 输出格式

`--json` 输出结构：

```json
{
  "scan_id": "20260611-123456-abc",
  "project": "my-skill",
  "risk": "critical",
  "risk_score": 100,
  "summary": {
    "components": 0,
    "findings": 3,
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0
  },
  "findings": [...]
}
```

---

## 9. FAQ

**Q: 扫描报 "database is locked"？**
A: 前一个 sync 进程被中断导致。参考运维文档的「数据库锁定恢复」章节。

**Q: 漏洞扫描显示 0 个漏洞？**
A: 确认已执行 `sca-cli sync --all` 同步了漏洞库。使用 `sca-cli db status` 查看数据库状态。

**Q: 离线环境怎么更新漏洞库？**
A: 参考运维文档的「离线环境更新」章节，使用 `--offline-export` / `--offline-import`。

**Q: 报告在哪？**
A: 默认输出到 `~/.sca-cli/reports/` 目录下。

**Q: 如何只扫规则、不扫漏洞？**
A: `sca-cli scan ./target --no-vuln`（默认只扫描规则和 SBOM）。

**Q: 扫描结果怎么集成到 Jenkins？**
A: 使用 `--json` 输出，然后通过 `jq` 提取风险等级判断构建是否通过。

---

> **相关文档：**
> - [运维手册](sca-cli_OPS_GUIDE.md) — 数据同步、更新、故障恢复
> - [开发规范](sca-cli_SPEC_v2.md) — 项目架构与开发指引
> - [实现说明](sca-cli_IMPLEMENTATION.md) — 当前实现状态与待办
