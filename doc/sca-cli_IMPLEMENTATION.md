# sca-cli v2 实现说明

本文档记录当前实现与 `doc/sca-cli_SPEC_v2.md` 的对应关系。

## 已实现能力

- Python 3.11+ 项目骨架，源码位于 `src/sca_cli`。
- Typer CLI 入口：`version`、`init`、`doctor`、`scan`、`sync`、`intel report`、`rules list/validate`、`db status/reset`。
- 默认数据目录：`~/.sca-cli`，支持 `--home` 覆盖。
- SQLite 初始化，包含规格中的扫描、漏洞、规则、同步、报告相关表。
- 输入处理：本地目录、本地 zip/tar/tgz、Git URL、HTTP/HTTPS 归档 URL。
- zip/tar 安全解压，阻止路径穿越和 tar link 成员。
- 项目识别：Python、JavaScript/TypeScript、MCP、AI Plugin、Agent Skill、mixed。
- SBOM：优先调用 Syft；Syft 缺失时使用内置轻量解析器生成 CycloneDX JSON。
- 漏洞扫描：`--vuln` 时调用 Grype、pip-audit、npm audit；工具缺失时记录 warning 并继续。
- 规则扫描：Skill/MCP/Plugin 元数据、安装脚本、高危 Python/JS API。
- findings 归一化、去重、风险评分。
- 报告输出：HTML、Markdown、JSON；报告目录包含 `sbom.cyclonedx.json` 和 `raw/` 原始扫描器输出。
- 同步：SPDX 许可证、OSV PyPI/npm zip、NVD modified feed、GHSA advisory database、AI-Infra-Guard 规则缓存、Grype DB、离线导入/导出。
- 情报报告：按时间范围、生态和严重性从本地 SQLite 查询漏洞并生成 HTML/Markdown/JSON。
- pytest 覆盖：安全解压、项目识别、轻量依赖解析、规则扫描、报告生成。

## 常用命令

```powershell
python -m pip install -e ".[dev]"
sca-cli init
sca-cli doctor
sca-cli scan .\tests\fixtures\mcp_command_tool --report
sca-cli scan .\tests\fixtures\js_postinstall_risk --rules --report --format html,json
sca-cli sync --source spdx
sca-cli intel report --range 24h
python -m pytest
```

## 外部工具降级行为

- Syft 缺失：降级到内置依赖解析器，报告中提示 SBOM 完整性降低。
- Grype 缺失：`--vuln` 的通用漏洞扫描跳过并记录 warning。
- pip-audit 缺失：Python 专项漏洞扫描跳过并记录 warning。
- npm 缺失或无 lockfile：npm audit 跳过并记录 warning。
- git 缺失：扫描 Git URL、同步 GHSA/AIG 时失败并记录清晰错误。

## 仍可增强的方向

- 更完整的 OSV/GHSA/NVD affected range 语义解析。
- ScanCode 许可证策略扫描。
- SARIF/PDF 输出。
- Python AST 与 JavaScript AST 深度扫描。
- Typosquatting 和恶意包情报库。
