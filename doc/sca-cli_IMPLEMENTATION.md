# sca-cli v2 实现说明

本文档记录当前实现与 `doc/sca-cli_SPEC_v2.md` 的对应关系。

## 验证状态

| 验证项 | 状态 |
|--------|------|
| `sca-cli init --force` | ✅ |
| `sca-cli doctor` | ✅ (Syft/Grype/pip-audit/npm/git 全部就绪) |
| `sca-cli scan python_safe_skill` | ✅ |
| `sca-cli scan mcp_command_tool --rules --report` | ✅ CRITICAL (100) |
| `sca-cli scan js_postinstall_risk --rules --report` | ✅ CRITICAL (100) |
| `sca-cli scan mcp_prompt_injection --rules --report` | ✅ CRITICAL (100) |
| `python -m pytest -v` | ✅ **193 passed** |
| Git push (main) | ✅ |

## 已实现能力

### P0 必须完成 — 全部完成

- Python 3.11+ 项目骨架，源码位于 `src/sca_cli`。
- Typer CLI 入口：`version`、`init`、`doctor`、`scan`、`sync`、`intel report`、`rules list/validate`、`db status/reset`。
- 默认数据目录：`~/.sca-cli`，支持 `--home` 覆盖。
- SQLite 初始化，包含 21 张表（settings, sources, sync_runs, raw_advisories, vulnerabilities, vulnerability_aliases, affected_packages, affected_ranges, licenses, license_policies, rulesets, rules, rule_import_errors, scan_targets, scan_jobs, scan_components, scan_sboms, scan_findings, scan_rule_hits, reports, intel_reports）。
- 输入处理：本地目录、本地 zip/tar/tgz、Git URL、HTTP/HTTPS 归档 URL。
- zip/tar 安全解压，阻止路径穿越和 tar link 成员。
- 项目识别：Python、JavaScript/TypeScript、MCP、AI Plugin、Agent Skill、mixed。
- SBOM：优先调用 Syft；Syft 缺失时使用内置轻量解析器生成 CycloneDX JSON。
- 漏洞扫描：`--vuln` 时调用 Grype、pip-audit、npm audit；工具缺失时记录 warning 并继续。
- 规则扫描：Skill/MCP/Plugin 元数据、安装脚本、高危 Python/JS API。
- findings 归一化、去重、风险评分。
- 报告输出：HTML、Markdown、JSON；报告目录包含 `sbom.cyclonedx.json` 和 `raw/` 原始扫描器输出。

### P1 建议完成 — 全部完成

- OSV 同步（PyPI/npm 全量 zip）
- GHSA 同步（git clone advisory-database）
- NVD 同步（modified feed）
- SPDX 同步（licenses.json）
- AI-Infra-Guard 规则导入（git clone + 转换）
- Grype DB 更新（grype db update）
- intel report（按时间范围、生态和严重性）
- 离线导入/导出（zip bundle）
- 规则校验命令（rules validate）
- 9 个测试 fixtures（python_safe/vulnerable/malicious, js_safe/vulnerable/postinstall, mcp_command/prompt_injection, mixed）

### SPEC 20 测试要求 — 全部覆盖

| 测试项 | 文件 | 状态 |
|--------|------|------|
| URL 类型识别 | test_input.py | ✅ 27 tests |
| zip 安全解压 | test_core.py | ✅ |
| 项目类型识别 | test_project_detect.py | ✅ 25 tests |
| Python 依赖解析 | test_core.py | ✅ |
| JS 依赖解析 | test_core.py | ✅ |
| YAML 规则加载 | test_rules_engine.py | ✅ 27 tests |
| 规则匹配 | test_rules_engine.py | ✅ |
| finding 去重 | test_normalize.py | ✅ 36 tests |
| SQLite 初始化 | (covered by init) | ✅ |
| 报告生成 | test_reports.py | ✅ 18 tests |
| 同步逻辑 | test_sync.py | ✅ 20 tests |

### 外部工具（已安装）

- **Syft** 1.45.1 — SBOM 生成
- **Grype** 0.114.0 — 通用漏洞扫描
- **pip-audit** 2.10.1 — Python 专项漏洞扫描
- **npm** — JS 专项漏洞扫描
- **git** — Git URL 下载 & 库同步

## 内置规则清单

### Skill 元数据 (5 条)
| ID | 名称 | 等级 |
|-----|------|------|
| SKILL-META-001 | Tool description contains instruction override | high |
| SKILL-META-002 | Tool description hides behavior from user | high |
| SKILL-META-003 | Tool asks model to exfiltrate data | critical |
| SKILL-META-004 | Tool claims official identity | medium |
| SKILL-META-005 | Tool requests broad file access | high |

### MCP 工具 (5 条)
| ID | 名称 | 等级 |
|-----|------|------|
| MCP-TOOL-001 | Tool accepts arbitrary file path | high |
| MCP-TOOL-002 | Tool accepts arbitrary URL | high |
| MCP-TOOL-003 | Tool accepts SQL query | high |
| MCP-TOOL-004 | Tool accepts arbitrary command | critical |
| MCP-TOOL-005 | Tool description contains prompt injection | high |

### Python (5 条)
| ID | 名称 | 等级 |
|-----|------|------|
| PY-HIGHAPI-001 | Use of eval/exec | high |
| PY-HIGHAPI-002 | Use of subprocess/os.system | high |
| PY-HIGHAPI-003 | pickle.loads usage | medium |
| PY-HIGHAPI-004 | yaml.load without safe loader | medium |
| PY-SECRET-001 | Reads secret-bearing files | high |

### Python Install (2 条)
| ID | 名称 | 等级 |
|-----|------|------|
| PY-INSTALL-001 | setup.py executes shell command | critical |
| PY-INSTALL-002 | setup.py downloads remote script | critical |

### JavaScript (4 条)
| ID | 名称 | 等级 |
|-----|------|------|
| JS-HIGHAPI-001 | Use of eval/Function constructor | high |
| JS-HIGHAPI-002 | child_process execution | high |
| JS-HIGHAPI-003 | Reads process.env | medium |
| JS-NET-001 | Sends data to external URL | medium |

### JavaScript Install (2 条)
| ID | 名称 | 等级 |
|-----|------|------|
| JS-INSTALL-001 | postinstall executes shell command | critical |
| JS-INSTALL-002 | install script downloads remote code | critical |

### Plugin OpenAPI (1 条)
| ID | 名称 | 等级 |
|-----|------|------|
| PLUGIN-OPENAPI-001 | OpenAPI exposes high-risk administrative operation | medium |

## 常用命令

```bash
pip install -e ".[dev]"
sca-cli init --force
sca-cli doctor
sca-cli sync --all              # 同步所有漏洞库（需要网络）
sca-cli scan tests/fixtures/python_safe_skill --report
sca-cli scan tests/fixtures/mcp_command_tool --rules --report
sca-cli scan tests/fixtures/js_postinstall_risk --rules --report
sca-cli intel report --range 24h
python -m pytest -v
```

## 新增文件（本轮）

- `README.md` — 项目 README
- `src/sca_cli/utils/logging.py` — 日志工具
- `src/sca_cli/reports/templates/scan_report.html.j2` — 增强版企业级 HTML 报告（13 节）
- `src/sca_cli/reports/templates/scan_report.md.j2` — 结构化 Markdown 报告
- `src/sca_cli/reports/templates/intel_report.html.j2` — 增强版情报 HTML 报告
- `src/sca_cli/reports/templates/intel_report.md.j2` — 增强版情报 Markdown 报告
- `tests/test_input.py` — 27 个输入处理测试
- `tests/test_project_detect.py` — 25 个项目识别测试
- `tests/test_rules_engine.py` — 27 个规则引擎测试
- `tests/test_normalize.py` — 36 个归一化测试
- `tests/test_reports.py` — 18 个报告生成测试
- `tests/test_sync.py` — 20 个同步逻辑测试
- `tests/fixtures/python_vulnerable_skill/` — 漏洞 Python 示例
- `tests/fixtures/python_malicious_setup/` — 恶意 setup.py 示例
- `tests/fixtures/js_safe_skill/` — 安全 JS 示例
- `tests/fixtures/js_vulnerable_skill/` — 漏洞 JS 示例
- `tests/fixtures/mcp_prompt_injection/` — Prompt 注入 MCP 示例
- `tests/fixtures/mixed_python_js_skill/` — Python+JS 混合示例

## 外部工具降级行为

- Syft 缺失：降级到内置依赖解析器，报告中提示 SBOM 完整性降低。
- Grype 缺失：`--vuln` 的通用漏洞扫描跳过并记录 warning。
- pip-audit 缺失：Python 专项漏洞扫描跳过并记录 warning。
- npm 缺失或无 lockfile：npm audit 跳过并记录 warning。
- git 缺失：扫描 Git URL、同步 GHSA/AIG 时失败并记录清晰错误。

## 仍可增强的方向（P2）

1. ScanCode 许可证策略扫描。
2. Typosquatting 检测和恶意包情报库。
3. Python AST 与 JavaScript AST 深度扫描。
4. OpenAPI 风险扫描增强（路径参数分析等）。
5. SARIF 输出格式支持。
6. PDF 报告输出（Playwright/WeasyPrint）。
7. CI/CD 模式（exit code 策略、GitHub Action）。
8. Web UI 管理界面。
