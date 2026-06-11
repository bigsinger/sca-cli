# sca-cli — Agent Skill 供应链扫描 CLI

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**sca-cli** 是一个本地优先、可离线化、面向 Agent Skill 的供应链安全扫描 CLI 工具。

## 定位

不是传统通用 SCA 扫描器，而是聚焦以下扫描对象：

- **Agent Skill** 技能包（`skill.json`、`agent.json`、`tools/`）
- **MCP Server / MCP Tool**（`mcp.json`、FastMCP 服务）
- **AI Plugin**（`ai-plugin.json`、`openapi.yaml`）
- **Python** 工具包（`pyproject.toml`、`requirements.txt`）
- **JavaScript / TypeScript** 工具包（`package.json`）
- LLM Agent 的 Tool / Plugin / Skill 目录

## 快速开始

```bash
# 安装
pip install -e ".[dev]"

# 初始化数据目录
sca-cli init

# 检查环境
sca-cli doctor

# 扫描本地目录
sca-cli scan ./my-skill

# 扫描 + 漏洞检测 + 报告
sca-cli scan ./my-skill --vuln --report

# 扫描 Git URL 或 zip
sca-cli scan https://github.com/example/agent-skill.git --vuln --report
sca-cli scan https://example.com/skill.zip --vuln --report

# 同步漏洞库
sca-cli sync --all

# 生成威胁情报报告
sca-cli intel report --range 24h
```

## 核心能力

| 能力 | 说明 |
|------|------|
| **SBOM 生成** | 优先调用 Syft，自动降级为内置 lockfile 解析器 |
| **漏洞扫描** | Grype（通用）+ pip-audit（Python）+ npm audit（JS） |
| **规则扫描** | Skill/MCP/Plugin 元数据、安装脚本、高危 API 内置规则 |
| **输入支持** | 本地目录、zip/tar、Git URL、HTTP 归档 URL |
| **安全约束** | 不执行被扫描代码、Zip Slip 防护、URL 下载限大小 |
| **报告输出** | HTML（自带 CSS）、Markdown、JSON |
| **本地知识库** | SQLite 存储漏洞、许可证、规则、扫描历史 |
| **数据同步** | OSV / GHSA / NVD / SPDX / AI-Infra-Guard |
| **离线支持** | 离线导出/导入数据包 |
| **威胁情报** | 按时间/生态/严重性生成情报报告 |

## 命令参考

```text
sca-cli --help              # 帮助
sca-cli init                # 初始化数据目录
sca-cli doctor              # 环境检查
sca-cli scan <target>       # 扫描目标
sca-cli sync --all          # 同步漏洞库
sca-cli intel report        # 生成情报报告
sca-cli rules list          # 列出规则
sca-cli rules validate      # 校验规则
sca-cli db status           # 数据库状态
sca-cli db reset            # 重置数据库
```

### scan 详细参数

```bash
sca-cli scan <target> \
  --name <project-name> \          # 项目名称
  --type auto|python|javascript|mcp|plugin|mixed  # 强制类型
  --vuln                           # 启用漏洞扫描
  --rules/--no-rules               # 启用/禁用规则扫描
  --sbom/--no-sbom                 # 启用/禁用 SBOM
  --license                        # 启用许可证扫描
  --report                         # 生成报告
  --format html,md,json            # 报告格式
  --scanner auto|all               # 扫描器选择
  --fail-on critical|high|medium   # 失败阈值
  --offline                        # 离线模式
  --json                           # JSON 输出
```

## 外部工具依赖

| 工具 | 用途 | 安装方式 |
|------|------|----------|
| [Syft](https://github.com/anchore/syft) | SBOM 生成 | `winget install Anchore.Syft` |
| [Grype](https://github.com/anchore/grype) | 通用漏洞扫描 | `winget install Anchore.Grype` |
| [pip-audit](https://github.com/pypa/pip-audit) | Python 漏洞扫描 | `pip install pip-audit` |
| npm | JS 漏洞扫描 | Node.js 内置 |
| git | Git URL 下载 | Git SCM 内置 |

所有工具缺失时均有降级行为，不会直接崩溃。

## 扫描报告

HTML 报告自带 CSS，不依赖外部资源，包含以下章节：

1. 封面 & 扫描摘要
2. 风险评级
3. Agent Skill 类型识别
4. 组件与 SBOM 概览
5. 漏洞扫描结果
6. 元数据风险（MCP / Plugin / Skill）
7. 安装脚本风险
8. 高危 API 使用
9. 许可证风险
10. 修复建议
11. 附录：组件清单

## 开发

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行测试
pytest -v
```

## 项目结构

```
sca-cli/
├── pyproject.toml
├── README.md
├── doc/
│   ├── sca-cli_SPEC_v2.md          # 开发规范
│   └── sca-cli_IMPLEMENTATION.md   # 实现记录
├── src/sca_cli/
│   ├── main.py                     # CLI 入口
│   ├── cli/                        # 命令模块
│   ├── core/                       # 核心功能
│   ├── db/                         # 数据库
│   ├── scanners/                   # 扫描器
│   ├── rules/                      # 规则引擎
│   ├── rules_builtin/              # 内置规则
│   ├── reports/                    # 报告生成
│   ├── normalize/                  # 归一化
│   └── utils/                      # 工具
├── rules_builtin/                  # 用户规则目录
└── tests/
    ├── fixtures/                   # 测试夹具
    ├── test_core.py
    └── test_rules_reports.py
```

## 许可证

MIT
