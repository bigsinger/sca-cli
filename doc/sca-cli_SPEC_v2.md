# sca-cli_SPEC_v2：Agent Skill 供应链扫描 CLI 开发规范

> 版本：v2.0  
> 定位：面向 Agent Skill / MCP Server / AI Plugin / Tool 包的供应链与漏洞扫描 CLI  
> 目标读者：Codex / AI 编程助手 / Python 开发工程师 / 安全产品经理  
> 首发平台：Windows 本地运行  
> 跨平台要求：Windows / macOS / Linux 兼容  
> 开发语言：Python 3.11+  
> 运行形态：本地 CLI 工具，后续可扩展为 Web/API 服务  
> 项目名称：`sca-cli`  

---

## 0. 文档目标

本文档用于指导 Codex 一次性开发一个可运行的本地 CLI 工具 `sca-cli`。

本项目不再定位为传统通用 SCA 扫描器，而是定位为：

```text
Agent Skill 供应链扫描工具
```

重点扫描对象包括：

1. Agent Skill 技能包；
2. MCP Server / MCP Tool；
3. AI Plugin；
4. Python 工具包；
5. JavaScript / TypeScript 工具包；
6. LLM Agent 的 Tool / Plugin / Skill 目录；
7. 未来可扩展到 Dify、Langflow、FastGPT、Open WebUI、ComfyUI、Ollama 等 AI Infra 组件。

本工具第一阶段重点解决：

```text
输入 Skill 包 / Git URL / 目录 / zip
    ↓
识别 Python / JS / MCP / Plugin 结构
    ↓
生成 SBOM
    ↓
扫描依赖漏洞
    ↓
扫描安装脚本风险
    ↓
扫描 Skill / MCP 元数据风险
    ↓
扫描高危 API 使用
    ↓
同步开源漏洞库 / 规则库到本地
    ↓
生成企业级扫描报告和威胁情报报告
```

---

## 1. 设计原则

### 1.1 产品定位

`sca-cli` 是一个本地优先、可离线化、面向 Agent Skill 的供应链安全 CLI 工具。

它不是单纯包装开源扫描器，也不是传统 Java SCA 扫描器。

它的核心价值是：

```text
传统 SCA 能力
+ Python / JS 生态专项漏洞扫描
+ Agent Skill / MCP / Plugin 元数据安全扫描
+ 安装脚本与高危行为扫描
+ 本地漏洞库与规则库同步
+ 企业级报告输出
+ 威胁情报报告生成
```

### 1.2 开发约束

1. 必须使用 Python 开发；
2. 首发必须能在 Windows 上运行；
3. 代码必须跨平台，不得写死 Windows 路径；
4. 数据库存储使用本地 SQLite；
5. 报告输出必须支持 HTML 和 Markdown；
6. PDF 报告作为可选增强，若环境不满足应降级为 HTML；
7. 外部扫描工具不存在时，必须给出清晰提示，不得直接崩溃；
8. 所有命令必须支持 `--json` 输出，便于 CI/CD 集成；
9. 所有扫描任务必须保存结构化结果到 SQLite；
10. 默认扫描不联网，除非用户执行 `sync` 或输入 URL 需要下载；
11. 任何远程 URL 下载必须落到隔离工作目录；
12. 解压 zip/tar 必须防止 Zip Slip 路径穿越；
13. 不执行被扫描项目中的安装脚本；
14. 不运行被扫描 Skill 的业务代码；
15. 默认仅做静态扫描和外部工具扫描。

---

## 2. 核心场景

### 2.1 场景一：扫描 Agent Skill 包

用户输入：

```bash
sca-cli scan ./my-skill --vuln --report
```

系统行为：

1. 识别目录类型；
2. 判断是否 Python / JS / MCP / Plugin；
3. 生成 SBOM；
4. 执行漏洞扫描；
5. 执行 Skill 规则扫描；
6. 执行安装脚本风险扫描；
7. 执行高危 API 扫描；
8. 输出报告。

### 2.2 场景二：扫描 Git URL 或 zip URL

用户输入：

```bash
sca-cli scan https://github.com/example/agent-skill.git --vuln --report
sca-cli scan https://example.com/skill.zip --vuln --report
```

系统行为：

1. 判断 URL 类型；
2. 如果是 Git URL，使用 `git clone --depth 1` 下载；
3. 如果是 zip/tar URL，下载到本地缓存目录；
4. 解压到工作目录；
5. 按目录扫描。

### 2.3 场景三：同步漏洞库和规则库

用户输入：

```bash
sca-cli sync --all
sca-cli sync --source osv,ghsa,nvd,spdx,aig
```

系统行为：

1. 首次全量下载；
2. 后续按更新时间增量同步；
3. 保存同步状态；
4. 支持失败重试；
5. 支持离线导出和导入。

### 2.4 场景四：生成威胁情报报告

用户输入：

```bash
sca-cli intel report --range 24h
sca-cli intel report --from 2026-06-01 --to 2026-06-11 --ecosystem pypi,npm --format html
```

系统行为：

1. 查询本地 SQLite 中指定时间范围内新增或更新的漏洞；
2. 按生态、严重性、是否影响 Agent Skill 常用组件聚合；
3. 生成企业级威胁情报报告。

---

## 3. 技术选型

### 3.1 主体技术栈

| 模块 | 选型 |
|---|---|
| 开发语言 | Python 3.11+ |
| CLI 框架 | Typer |
| 控制台输出 | Rich |
| 数据库 | SQLite |
| ORM | SQLAlchemy 2.x |
| 数据校验 | Pydantic v2 |
| HTTP 请求 | httpx |
| 模板引擎 | Jinja2 |
| Markdown 生成 | Python 字符串模板 / Jinja2 |
| HTML 报告 | Jinja2 + 内置 CSS |
| PDF 报告 | 可选 Playwright / WeasyPrint，默认不强制 |
| YAML 解析 | PyYAML / ruamel.yaml |
| JSON 处理 | orjson 优先，内置 json 兜底 |
| 压缩包处理 | zipfile / tarfile |
| Git 下载 | git CLI，缺失时提示安装 |
| 调用外部工具 | subprocess |
| 测试 | pytest |
| 打包 | pyproject.toml + console_scripts |

### 3.2 外部扫描工具选型

| 工具 | 用途 | 是否必需 | 说明 |
|---|---|---|---|
| Syft | 生成 SBOM | 推荐必装 | 默认 SBOM 生成器 |
| Grype | SBOM / 文件系统漏洞扫描 | 推荐必装 | 通用漏洞扫描 |
| pip-audit | Python 依赖漏洞扫描 | 推荐必装 | Python Skill 专项 |
| npm audit | Node.js 依赖漏洞扫描 | 推荐可用 | JS/TS Skill 专项 |
| ScanCode Toolkit | 许可证扫描 | 可选 | 第二阶段增强 |
| Dependency-Check | Java 扫描 | 可选 | 仅作为兼容扩展，不作为主引擎 |
| AI-Infra-Guard 规则库 | AI/MCP 专项规则 | 可选但推荐同步 | 导入 data/fingerprints、data/vuln、data/mcp |

### 3.3 为什么不是 Dependency-Check 主线

本项目重点不是 Java/Maven 企业应用，而是 Agent Skill 供应链扫描。

主要对象是：

```text
Python Skill
Node.js Skill
MCP Server
AI Plugin
Agent Tool 包
```

Dependency-Check 的强项是传统 Java、NVD、CPE、H2 本地库。它可以作为可选扩展，但不应作为主路径。

本项目主路径应为：

```text
Syft：统一 SBOM
Grype：通用漏洞扫描
pip-audit：Python 专项漏洞扫描
npm audit：JS 专项漏洞扫描
OSV / GHSA / NVD：本地情报库
YAML 规则：Skill / MCP / Plugin / 安装脚本 / 高危 API
AI-Infra-Guard：AI Infra 和 MCP 专项规则包
```

---

## 4. 总体架构

```text
┌──────────────────────────────────────┐
│ sca-cli                               │
│ scan / sync / intel / rules / db       │
└──────────────────┬───────────────────┘
                   ↓
┌──────────────────────────────────────┐
│ 输入处理层                              │
│ URL下载 / Git clone / zip解压 / 目录扫描 │
└──────────────────┬───────────────────┘
                   ↓
┌──────────────────────────────────────┐
│ 项目识别层                              │
│ Python / JS / MCP / Plugin / AI Infra  │
└──────────────────┬───────────────────┘
                   ↓
┌──────────────────────────────────────┐
│ 组件与元数据采集层                       │
│ Syft SBOM / lockfile / manifest / tool │
└──────────────────┬───────────────────┘
                   ↓
┌──────────────────────────────────────┐
│ 扫描引擎层                              │
│ Grype / pip-audit / npm audit / rules  │
└──────────────────┬───────────────────┘
                   ↓
┌──────────────────────────────────────┐
│ 本地知识库层                            │
│ SQLite: OSV / GHSA / NVD / SPDX / AIG  │
└──────────────────┬───────────────────┘
                   ↓
┌──────────────────────────────────────┐
│ 结果归一化层                            │
│ findings / risk score / dedupe         │
└──────────────────┬───────────────────┘
                   ↓
┌──────────────────────────────────────┐
│ 报告层                                  │
│ HTML / Markdown / JSON / PDF可选        │
└──────────────────────────────────────┘
```

---

## 5. CLI 命令设计

### 5.1 顶层命令

```bash
sca-cli --help
sca-cli version
sca-cli doctor
sca-cli init
sca-cli scan <target>
sca-cli sync
sca-cli intel report
sca-cli rules list
sca-cli rules validate
sca-cli db status
sca-cli db reset
```

### 5.2 `init` 命令

初始化本地目录、SQLite 数据库、默认配置和规则目录。

```bash
sca-cli init
sca-cli init --force
sca-cli init --home D:\sca-cli-data
```

默认数据目录：

| 平台 | 路径 |
|---|---|
| Windows | `%USERPROFILE%\.sca-cli` |
| macOS/Linux | `~/.sca-cli` |

初始化目录结构：

```text
.sca-cli/
├── config.yaml
├── sca-cli.db
├── cache/
├── downloads/
├── workspaces/
├── reports/
├── sbom/
├── rules/
│   ├── skill/
│   ├── mcp/
│   ├── python/
│   ├── javascript/
│   ├── malicious-packages/
│   └── ai-infra/
└── logs/
```

### 5.3 `doctor` 命令

检查运行环境。

```bash
sca-cli doctor
sca-cli doctor --json
```

检查内容：

1. Python 版本；
2. SQLite 可用性；
3. Syft 是否存在；
4. Grype 是否存在；
5. pip-audit 是否存在；
6. npm 是否存在；
7. git 是否存在；
8. 数据目录是否可写；
9. 数据库是否初始化；
10. 规则目录是否存在；
11. 上次同步时间；
12. Grype DB 状态；
13. 网络连通性，可选。

### 5.4 `scan` 命令

基础用法：

```bash
sca-cli scan <target>
```

完整参数：

```bash
sca-cli scan <target> \
  --name <project-name> \
  --type auto|python|javascript|mcp|plugin|mixed \
  --skill-mode agent|mcp|plugin|auto \
  --sbom \
  --vuln \
  --rules \
  --license \
  --report \
  --format html,md,json \
  --output ./reports \
  --scanner syft,grype,pip-audit,npm-audit,skill-rules \
  --fail-on critical|high|medium|low|none \
  --offline \
  --json
```

默认行为：

```text
--sbom 默认开启
--rules 默认开启
--vuln 默认关闭，用户指定后开启
--report 默认关闭，用户指定后生成
--format 默认 html,md,json
--scanner 默认 auto
```

示例：

```bash
sca-cli scan ./skills/weather --vuln --report
sca-cli scan ./skills/weather.zip --vuln --rules --report --format html,json
sca-cli scan https://github.com/example/mcp-server.git --vuln --report
sca-cli scan ./agent-plugin --skill-mode mcp --scanner all --fail-on high
```

### 5.5 `sync` 命令

同步漏洞库、许可证库、规则库。

```bash
sca-cli sync --all
sca-cli sync --source osv
sca-cli sync --source ghsa,nvd,spdx,aig
sca-cli sync --source grype-db
sca-cli sync --offline-import ./offline-bundle.zip
sca-cli sync --offline-export ./offline-bundle.zip
```

参数：

| 参数 | 说明 |
|---|---|
| `--all` | 同步所有启用数据源 |
| `--source` | 指定数据源 |
| `--full` | 强制全量同步 |
| `--since` | 指定增量起始时间 |
| `--offline-export` | 导出离线更新包 |
| `--offline-import` | 导入离线更新包 |
| `--no-verify-tls` | 调试用，不建议 |
| `--proxy` | 设置代理 |
| `--json` | JSON 输出 |

支持数据源：

```text
osv
nvd
ghsa
spdx
scancode-license
aig
grype-db
npm-advisory-meta
pypa-advisory
```

### 5.6 `intel report` 命令

生成威胁情报报告。

```bash
sca-cli intel report
sca-cli intel report --range 24h
sca-cli intel report --range 7d
sca-cli intel report --from 2026-06-01 --to 2026-06-11
sca-cli intel report --ecosystem pypi,npm --focus agent --format html,md,json
```

参数：

| 参数 | 说明 |
|---|---|
| `--range` | 时间范围，默认 24h |
| `--from` | 开始日期 |
| `--to` | 结束日期 |
| `--ecosystem` | 生态过滤，例如 pypi,npm |
| `--severity` | 严重性过滤 |
| `--focus` | agent / ai / all |
| `--format` | html / md / json |
| `--output` | 输出目录 |

---

## 6. 输入处理规范

### 6.1 输入类型识别

`scan <target>` 支持：

| 输入 | 判断方式 | 处理 |
|---|---|---|
| 本地目录 | `Path.is_dir()` | 直接扫描 |
| 本地 zip | 后缀 `.zip` | 解压后扫描 |
| 本地 tar/tgz | `.tar`, `.tar.gz`, `.tgz` | 解压后扫描 |
| Git URL | `.git` 或 GitHub/GitLab URL | clone 到 workspace |
| HTTP zip URL | URL 后缀或 Content-Type | 下载后解压 |
| 普通 HTTP URL | 下载，若不是归档则报错 |

### 6.2 URL 下载安全要求

1. 限制最大下载大小，默认 500MB；
2. 支持 `--max-download-size`；
3. 下载文件保存到 `downloads/`；
4. 使用随机文件名；
5. 校验 Content-Length；
6. 不信任远程文件名；
7. 不自动执行下载文件。

### 6.3 解压安全要求

必须防止路径穿越：

```text
../../evil.py
/absolute/path/file
C:\Windows\evil.dll
```

解压前必须检查每个文件的目标路径是否仍在 workspace 内。

### 6.4 Workspace 规范

每次扫描创建独立工作目录：

```text
~/.sca-cli/workspaces/<scan_id>/
├── input/
├── extracted/
├── sbom/
├── raw-results/
└── normalized/
```

扫描结束默认保留结构化结果和报告，临时目录可通过配置清理。

---

## 7. 项目类型识别

### 7.1 Python Skill 识别

命中任一文件即认为可能是 Python 项目：

```text
requirements.txt
pyproject.toml
poetry.lock
Pipfile
Pipfile.lock
setup.py
setup.cfg
*.py
```

### 7.2 JavaScript / TypeScript Skill 识别

命中任一文件：

```text
package.json
package-lock.json
yarn.lock
pnpm-lock.yaml
*.js
*.ts
```

### 7.3 MCP Server 识别

命中任一特征：

```text
mcp.json
server.py 中出现 mcp.server / FastMCP / MCPServer
server.ts 中出现 MCPServer / @modelcontextprotocol
package.json dependencies 中包含 @modelcontextprotocol
pyproject.toml dependencies 中包含 mcp / modelcontextprotocol
目录中存在 tools/ 且包含 tool schema
```

### 7.4 AI Plugin 识别

命中任一文件：

```text
ai-plugin.json
openapi.yaml
openapi.yml
openapi.json
manifest.json
```

### 7.5 Agent Skill 识别

命中任一特征：

```text
skill.json
agent.json
tool.json
tools.json
plugin.yaml
plugin.json
manifest.yaml
manifest.json
prompts/
tools/
```

### 7.6 混合项目

如果同时存在 Python 和 JS，应标记为 `mixed`，同时启用 Python 和 JS 专项扫描。

---

## 8. 扫描引擎设计

### 8.1 扫描引擎清单

| 引擎 ID | 名称 | 默认 | 说明 |
|---|---|---|---|
| `syft` | SBOM 生成 | 开启 | 生成 CycloneDX JSON |
| `grype` | 通用漏洞扫描 | 用户指定 `--vuln` 后开启 | 扫 SBOM |
| `pip-audit` | Python 漏洞扫描 | Python 项目且 `--vuln` 后开启 | 扫 requirements / pyproject |
| `npm-audit` | JS 漏洞扫描 | JS 项目且 `--vuln` 后开启 | 扫 package-lock |
| `skill-rules` | Skill 规则扫描 | 开启 | 元数据和描述风险 |
| `install-script-rules` | 安装脚本风险 | 开启 | setup.py、package scripts |
| `high-risk-api-rules` | 高危 API 扫描 | 开启 | Python/JS 高危调用 |
| `license` | 许可证扫描 | 可选 | 从 SBOM 或 ScanCode |
| `aig-rules` | AI-Infra-Guard 规则 | 有规则时开启 | AI/MCP 专项 |

### 8.2 Syft SBOM 生成

命令模板：

```bash
syft <target_dir> -o cyclonedx-json=<output_file>
```

输出文件：

```text
sbom/<scan_id>.cyclonedx.json
```

要求：

1. 默认必须生成 SBOM；
2. Syft 不存在时：
   - 记录 warning；
   - 尝试使用内置 lockfile parser 生成简化 SBOM；
   - 报告中标记 SBOM 完整性降低。

简化 SBOM 至少支持：

1. `requirements.txt`；
2. `package-lock.json`；
3. `package.json`；
4. `pyproject.toml` 基础依赖字段。

### 8.3 Grype 漏洞扫描

命令模板：

```bash
grype sbom:<sbom_file> -o json --file <output_file>
```

要求：

1. 仅当 `--vuln` 开启；
2. 优先扫描 Syft SBOM；
3. 如果无 SBOM，可扫描目录；
4. 解析 Grype JSON，归一化为统一 finding；
5. 支持 `grype db update` 作为 `sync --source grype-db`。

### 8.4 pip-audit 扫描

适用：Python 项目。

优先级：

```text
poetry.lock > requirements.txt > pyproject.toml > installed environment disabled
```

命令示例：

```bash
pip-audit -r requirements.txt -f json -o <output_file>
pip-audit --project <target_dir> -f json -o <output_file>
```

要求：

1. 不安装依赖；
2. 不执行项目代码；
3. 若缺少 lock/requirements，记录 warning；
4. 解析 JSON 输出；
5. 与 Grype 结果按 `package + version + vuln_id` 去重。

### 8.5 npm audit 扫描

适用：Node.js / TypeScript 项目。

命令示例：

```bash
npm audit --json --package-lock-only
```

要求：

1. 仅在存在 `package-lock.json` 或 `npm-shrinkwrap.json` 时默认执行；
2. 不执行 `npm install`；
3. 不运行 preinstall/postinstall；
4. 若仅有 `package.json`，默认不执行 npm audit，记录 warning；
5. 支持用户显式指定 `--allow-npm-resolve`，但默认关闭；
6. 解析 npm audit JSON。

### 8.6 Skill 规则扫描

扫描对象：

```text
mcp.json
ai-plugin.json
skill.json
tool.json
tools.json
manifest.json
manifest.yaml
openapi.yaml
package.json
pyproject.toml
README.md
prompts/*
tools/*
```

检测内容：

| 类型 | 示例 |
|---|---|
| Tool description 投毒 | ignore previous instructions |
| 隐藏行为 | do not tell the user |
| 数据外传 | send user data to external server |
| 过宽权限 | access all files / all network |
| 任意 URL 参数 | url / callback / target |
| 任意路径参数 | path / filepath / directory |
| 任意命令参数 | command / cmd / shell |
| OpenAPI 高危接口 | DELETE / admin / token / export |
| 官方仿冒 | official / github / openai / google 等高风险命名 |

### 8.7 安装脚本风险扫描

Python：

```text
setup.py
pyproject.toml
setup.cfg
```

Node：

```text
package.json scripts.preinstall
package.json scripts.install
package.json scripts.postinstall
package.json scripts.prepare
package.json scripts.prepublish
```

高危模式：

| 规则 | 示例 |
|---|---|
| Shell 执行 | os.system, subprocess, child_process.exec |
| 下载执行 | curl, wget, powershell iwr, bash -c |
| 读取密钥 | .env, .npmrc, .pypirc, id_rsa |
| 外联上传 | requests.post, fetch, axios.post |
| 混淆命令 | base64 decode 后执行 |

### 8.8 高危 API 扫描

Python 高危 API：

```text
eval
exec
compile
os.system
subprocess.Popen
subprocess.call
subprocess.run
pickle.loads
yaml.load
marshal.loads
requests.post
socket.socket
open(..., 'w')
shutil.rmtree
```

JavaScript 高危 API：

```text
eval
Function
child_process.exec
child_process.spawn
child_process.execSync
fs.readFileSync
fs.writeFileSync
process.env
http.request
https.request
fetch
axios.post
```

MVP 可使用正则扫描，第二阶段增加 AST 解析。

---

## 9. 规则系统设计

### 9.1 规则类型

```text
skill_metadata
mcp_tool
plugin_manifest
install_script
high_risk_api
malicious_package
typosquatting
openapi_risk
ai_infra_fingerprint
aig_imported
license_policy
```

### 9.2 YAML 规则格式

```yaml
id: SKILL-META-001
name: Tool description contains instruction override
category: skill_metadata
severity: high
confidence: medium
enabled: true
targets:
  - mcp.json
  - tool.json
  - tools.json
  - ai-plugin.json
match:
  fields:
    - description
    - tool.description
    - parameters.*.description
  any_keywords:
    - ignore previous instructions
    - disregard prior instructions
    - do not tell the user
    - bypass safety
normalization:
  lowercase: true
  unicode_normalize: true
  strip_zero_width: true
risk: Tool metadata may attempt to inject instructions into the agent context.
remediation: Remove instruction-like content from tool descriptions and keep metadata purely functional.
references: []
```

### 9.3 安装脚本规则示例

```yaml
id: INSTALL-JS-001
name: NPM postinstall executes shell command
category: install_script
severity: high
confidence: high
enabled: true
targets:
  - package.json
match:
  json_paths:
    - $.scripts.preinstall
    - $.scripts.install
    - $.scripts.postinstall
    - $.scripts.prepare
  regex:
    - "child_process"
    - "curl\\s+.*\\|\\s*(sh|bash)"
    - "wget\\s+.*\\|\\s*(sh|bash)"
    - "powershell.*Invoke-WebRequest"
risk: Package installation may execute arbitrary shell commands.
remediation: Remove install-time command execution or require manual review.
```

### 9.4 MCP Tool 参数规则示例

```yaml
id: MCP-TOOL-004
name: MCP tool accepts arbitrary command parameter
category: mcp_tool
severity: critical
confidence: high
enabled: true
match:
  fields:
    - inputSchema.properties.*.description
    - inputSchema.properties.*.title
    - inputSchema.properties.*.name
  any_keywords:
    - command
    - shell
    - cmd
    - execute
condition:
  tool_description_keywords:
    - run
    - execute
    - terminal
risk: Tool may allow arbitrary command execution through agent-controlled input.
remediation: Restrict command parameters to allowlisted operations and require human approval.
```

### 9.5 规则加载顺序

```text
内置规则
→ 用户本地规则
→ AIG 导入规则
→ 项目级规则
```

后加载规则可以覆盖同 ID 规则，但必须记录覆盖来源。

---

## 10. 特征库与数据同步

### 10.1 同步源

| 来源 | 用途 |
|---|---|
| OSV | Python/npm 等生态漏洞主库 |
| GHSA | GitHub Advisory 数据 |
| NVD | CVE/CVSS/CWE/CPE 补充 |
| SPDX | 许可证标准库 |
| ScanCode LicenseDB | 许可证扩展库，可选 |
| Grype DB | Grype 自身漏洞数据库 |
| PyPA Advisory | Python 生态漏洞补充，可选 |
| npm audit advisory | npm 生态漏洞补充，可选 |
| AI-Infra-Guard | AI/MCP 指纹与漏洞规则 |

### 10.2 同步策略

1. 首次同步：全量；
2. 后续同步：按 `modified_since` 或源支持的增量参数；
3. 不支持增量的源：使用 ETag / Last-Modified / manifest hash；
4. 保存原始数据；
5. 保存归一化数据；
6. 同步失败不破坏已有库；
7. 使用事务写入；
8. 支持回滚；
9. 支持离线导入导出。

### 10.3 数据源状态表

每个源记录：

```text
source_name
source_url
last_full_sync_at
last_incremental_sync_at
last_success_at
last_error
etag
last_modified
record_count
status
```

### 10.4 AI-Infra-Guard 规则导入

同步来源：

```text
data/fingerprints/
data/vuln/
data/mcp/
```

导入方式：

1. 下载 GitHub 仓库 zip 或 git clone；
2. 读取指定目录 YAML / JSON 规则；
3. 转换为内部规则格式；
4. 标记 source=`aig`；
5. 保留原始文件路径；
6. 不兼容规则进入 `rules_import_errors` 表。

---

## 11. SQLite 数据库设计

### 11.1 表清单

```text
settings
sources
sync_runs
raw_advisories
vulnerabilities
vulnerability_aliases
affected_packages
affected_ranges
licenses
license_policies
rulesets
rules
rule_import_errors
scan_targets
scan_jobs
scan_components
scan_sboms
scan_findings
scan_rule_hits
reports
intel_reports
```

### 11.2 `sources`

```sql
CREATE TABLE sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,
  url TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_full_sync_at TEXT,
  last_incremental_sync_at TEXT,
  last_success_at TEXT,
  last_error TEXT,
  etag TEXT,
  last_modified TEXT,
  record_count INTEGER DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

### 11.3 `vulnerabilities`

```sql
CREATE TABLE vulnerabilities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  primary_id TEXT NOT NULL UNIQUE,
  title TEXT,
  description TEXT,
  severity TEXT,
  cvss_score REAL,
  cvss_vector TEXT,
  cwe TEXT,
  published_at TEXT,
  modified_at TEXT,
  source TEXT,
  references_json TEXT,
  remediation TEXT,
  raw_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

### 11.4 `vulnerability_aliases`

```sql
CREATE TABLE vulnerability_aliases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vulnerability_id INTEGER NOT NULL,
  alias TEXT NOT NULL,
  source TEXT,
  UNIQUE(vulnerability_id, alias)
);
```

### 11.5 `affected_packages`

```sql
CREATE TABLE affected_packages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vulnerability_id INTEGER NOT NULL,
  ecosystem TEXT NOT NULL,
  package_name TEXT NOT NULL,
  purl TEXT,
  fixed_versions_json TEXT,
  source TEXT,
  confidence TEXT DEFAULT 'medium',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

### 11.6 `affected_ranges`

```sql
CREATE TABLE affected_ranges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  affected_package_id INTEGER NOT NULL,
  range_type TEXT,
  introduced TEXT,
  fixed TEXT,
  last_affected TEXT,
  affected_versions_json TEXT,
  raw_range_json TEXT,
  created_at TEXT NOT NULL
);
```

### 11.7 `rules`

```sql
CREATE TABLE rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id TEXT NOT NULL UNIQUE,
  ruleset_id INTEGER,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  source TEXT,
  rule_yaml TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

### 11.8 `scan_jobs`

```sql
CREATE TABLE scan_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL UNIQUE,
  target TEXT NOT NULL,
  target_type TEXT,
  project_name TEXT,
  skill_type TEXT,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  options_json TEXT,
  summary_json TEXT,
  error TEXT
);
```

### 11.9 `scan_components`

```sql
CREATE TABLE scan_components (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  ecosystem TEXT,
  name TEXT NOT NULL,
  version TEXT,
  purl TEXT,
  type TEXT,
  evidence TEXT,
  source TEXT,
  licenses_json TEXT,
  created_at TEXT NOT NULL
);
```

### 11.10 `scan_findings`

```sql
CREATE TABLE scan_findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  component_name TEXT,
  component_version TEXT,
  ecosystem TEXT,
  vuln_id TEXT,
  rule_id TEXT,
  file_path TEXT,
  line_number INTEGER,
  evidence TEXT,
  remediation TEXT,
  source TEXT,
  raw_json TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(scan_id, finding_id)
);
```

### 11.11 索引

```sql
CREATE INDEX idx_vuln_modified ON vulnerabilities(modified_at);
CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX idx_alias_alias ON vulnerability_aliases(alias);
CREATE INDEX idx_affected_pkg ON affected_packages(ecosystem, package_name);
CREATE INDEX idx_scan_findings_scan ON scan_findings(scan_id);
CREATE INDEX idx_scan_findings_severity ON scan_findings(severity);
CREATE INDEX idx_scan_components_scan ON scan_components(scan_id);
```

---

## 12. 结果归一化与去重

### 12.1 Finding 统一模型

```json
{
  "finding_id": "sha256-derived-id",
  "category": "vulnerability|skill_risk|install_script|high_risk_api|license|malicious_package",
  "severity": "critical|high|medium|low|info",
  "title": "string",
  "description": "string",
  "component": {
    "ecosystem": "pypi",
    "name": "requests",
    "version": "2.19.0",
    "purl": "pkg:pypi/requests@2.19.0"
  },
  "vulnerability": {
    "id": "CVE-xxxx",
    "aliases": ["GHSA-xxxx"],
    "cvss": 9.8,
    "fixed_versions": []
  },
  "evidence": {
    "file": "package.json",
    "line": 12,
    "snippet": "postinstall: curl ..."
  },
  "source": "grype|pip-audit|npm-audit|rule|osv|aig",
  "remediation": "string"
}
```

### 12.2 去重规则

漏洞去重 key：

```text
ecosystem + package_name + version + normalized_vuln_id
```

规则命中去重 key：

```text
rule_id + file_path + line_number + evidence_hash
```

同一漏洞由多个扫描器命中时：

1. 合并 source；
2. 严重性取最高；
3. 证据保留多个；
4. 报告中显示“多引擎确认”。

---

## 13. 风险评分

### 13.1 严重性权重

| 等级 | 分数 |
|---|---:|
| critical | 100 |
| high | 80 |
| medium | 50 |
| low | 20 |
| info | 5 |

### 13.2 Agent Skill 加权

以下情况加权：

| 条件 | 加分 |
|---|---:|
| MCP tool 任意命令参数 | +25 |
| 安装脚本执行 shell | +20 |
| 读取环境变量 + 外联 | +20 |
| tool description 指令注入 | +15 |
| npm/pypi 高危漏洞 | +10 |
| 无 lockfile | +8 |
| 未知许可证 | +5 |
| 多引擎同时命中 | +5 |

最终风险等级：

| 分数 | 等级 |
|---:|---|
| 0-30 | Low |
| 31-60 | Medium |
| 61-85 | High |
| 86+ | Critical |

---

## 14. 报告设计

### 14.1 扫描报告格式

输出：

```text
reports/<scan_id>/
├── report.html
├── report.md
├── report.json
├── sbom.cyclonedx.json
└── raw/
    ├── grype.json
    ├── pip-audit.json
    └── npm-audit.json
```

### 14.2 HTML 报告章节

```text
1. 封面
2. 扫描摘要
3. 风险评级
4. Agent Skill 类型识别
5. 组件与 SBOM 概览
6. 漏洞扫描结果
7. Python / JS 专项扫描结果
8. MCP / Plugin / Skill 元数据风险
9. 安装脚本风险
10. 高危 API 使用
11. 许可证风险
12. 威胁情报关联
13. 修复建议
14. 附录：组件清单
15. 附录：原始扫描器信息
```

### 14.3 企业级视觉要求

1. HTML 自带 CSS，不依赖外网；
2. 标题、卡片、统计图使用纯 CSS；
3. 严重性使用醒目的标签；
4. Critical / High 风险置顶；
5. 每个 finding 必须有证据和修复建议；
6. 报告顶部显示工具版本、规则库版本、漏洞库更新时间。

### 14.4 威胁情报报告章节

```text
1. 报告摘要
2. 时间范围
3. 新增 / 更新漏洞统计
4. Python / npm 生态重点漏洞
5. Agent Skill 相关高风险组件
6. Critical / High 漏洞清单
7. 可能影响的组件类型
8. 修复优先级建议
9. 数据来源和同步状态
10. 附录：完整漏洞列表
```

---

## 15. 配置文件

默认 `config.yaml`：

```yaml
app:
  home: null
  log_level: INFO
  max_download_size_mb: 500
  keep_workspace_days: 7

scan:
  default_sbom: true
  default_rules: true
  default_vuln: false
  default_report: false
  fail_on: none
  offline: false

external_tools:
  syft: syft
  grype: grype
  pip_audit: pip-audit
  npm: npm
  git: git

sync:
  enabled_sources:
    - osv
    - ghsa
    - nvd
    - spdx
    - aig
  nvd_api_key: null
  proxy: null
  timeout_seconds: 60

rules:
  enabled_categories:
    - skill_metadata
    - mcp_tool
    - plugin_manifest
    - install_script
    - high_risk_api
    - malicious_package
    - openapi_risk
    - ai_infra_fingerprint

report:
  default_formats:
    - html
    - md
    - json
  company_name: null
  logo_path: null
```

---

## 16. 项目目录结构

```text
sca-cli/
├── pyproject.toml
├── README.md
├── src/
│   └── sca_cli/
│       ├── __init__.py
│       ├── main.py
│       ├── cli/
│       │   ├── scan.py
│       │   ├── sync.py
│       │   ├── intel.py
│       │   ├── doctor.py
│       │   ├── rules.py
│       │   └── db.py
│       ├── core/
│       │   ├── config.py
│       │   ├── paths.py
│       │   ├── workspace.py
│       │   ├── downloader.py
│       │   ├── extractor.py
│       │   ├── project_detect.py
│       │   └── subprocess_runner.py
│       ├── db/
│       │   ├── models.py
│       │   ├── session.py
│       │   ├── migrations.py
│       │   └── repositories.py
│       ├── scanners/
│       │   ├── base.py
│       │   ├── syft.py
│       │   ├── grype.py
│       │   ├── pip_audit.py
│       │   ├── npm_audit.py
│       │   ├── skill_rules.py
│       │   ├── install_script.py
│       │   ├── high_risk_api.py
│       │   └── license.py
│       ├── rules/
│       │   ├── loader.py
│       │   ├── engine.py
│       │   ├── matcher.py
│       │   └── normalizer.py
│       ├── sync/
│       │   ├── base.py
│       │   ├── osv.py
│       │   ├── ghsa.py
│       │   ├── nvd.py
│       │   ├── spdx.py
│       │   ├── aig.py
│       │   └── grype_db.py
│       ├── normalize/
│       │   ├── components.py
│       │   ├── vulnerabilities.py
│       │   ├── findings.py
│       │   └── versions.py
│       ├── reports/
│       │   ├── generator.py
│       │   ├── templates/
│       │   │   ├── scan_report.html.j2
│       │   │   ├── scan_report.md.j2
│       │   │   ├── intel_report.html.j2
│       │   │   └── intel_report.md.j2
│       │   └── assets/
│       │       └── report.css
│       └── utils/
│           ├── time.py
│           ├── hashing.py
│           ├── json.py
│           └── logging.py
├── rules_builtin/
│   ├── skill/
│   ├── mcp/
│   ├── python/
│   ├── javascript/
│   └── install_scripts/
└── tests/
    ├── fixtures/
    ├── test_scan.py
    ├── test_rules.py
    ├── test_sync.py
    └── test_reports.py
```

---

## 17. 内置规则清单 MVP

### 17.1 Skill 元数据规则

| ID | 名称 | 等级 |
|---|---|---|
| SKILL-META-001 | Tool description contains instruction override | high |
| SKILL-META-002 | Tool description hides behavior from user | high |
| SKILL-META-003 | Tool asks model to exfiltrate data | critical |
| SKILL-META-004 | Tool claims official identity | medium |
| SKILL-META-005 | Tool requests broad file access | high |

### 17.2 MCP 规则

| ID | 名称 | 等级 |
|---|---|---|
| MCP-TOOL-001 | Tool accepts arbitrary file path | high |
| MCP-TOOL-002 | Tool accepts arbitrary URL | high |
| MCP-TOOL-003 | Tool accepts SQL query | high |
| MCP-TOOL-004 | Tool accepts arbitrary command | critical |
| MCP-TOOL-005 | Tool description contains prompt injection | high |

### 17.3 Python 规则

| ID | 名称 | 等级 |
|---|---|---|
| PY-HIGHAPI-001 | Use of eval/exec | high |
| PY-HIGHAPI-002 | Use of subprocess/os.system | high |
| PY-HIGHAPI-003 | pickle.loads usage | medium |
| PY-HIGHAPI-004 | yaml.load without safe loader | medium |
| PY-INSTALL-001 | setup.py executes shell command | critical |
| PY-INSTALL-002 | setup.py downloads remote script | critical |
| PY-SECRET-001 | Reads .env or SSH key | high |

### 17.4 JavaScript 规则

| ID | 名称 | 等级 |
|---|---|---|
| JS-HIGHAPI-001 | Use of eval/Function | high |
| JS-HIGHAPI-002 | child_process execution | high |
| JS-HIGHAPI-003 | Reads process.env | medium |
| JS-INSTALL-001 | postinstall executes shell | critical |
| JS-INSTALL-002 | install script downloads remote code | critical |
| JS-NET-001 | Sends data to external URL | medium |

---

## 18. 错误处理要求

### 18.1 外部工具缺失

如果 Syft 缺失：

```text
WARNING: Syft not found. Falling back to built-in lightweight dependency parser. SBOM completeness may be reduced.
```

如果 Grype 缺失且用户开启 `--vuln`：

```text
ERROR: Grype is required for generic vulnerability scanning. Install grype or disable --vuln.
```

如果 pip-audit 缺失：

```text
WARNING: pip-audit not found. Python-specific vulnerability scan skipped.
```

如果 npm 缺失：

```text
WARNING: npm not found. JavaScript-specific npm audit skipped.
```

### 18.2 同步失败

同步失败不得清空已有数据。必须记录：

1. 失败源；
2. 失败时间；
3. HTTP 状态；
4. 异常信息；
5. 是否使用旧数据继续。

---

## 19. 安全要求

1. 不执行被扫描 Skill；
2. 不执行 `npm install`；
3. 不执行 `pip install`；
4. 不执行 setup.py；
5. 不执行 package scripts；
6. 不解析不可信 YAML 的 Python 对象，仅使用 safe_load；
7. 解压防路径穿越；
8. URL 下载限制大小；
9. 外部命令参数必须列表化，不允许 shell=True；
10. 报告中显示代码片段时必须 HTML escape；
11. SQLite 路径必须在应用 home 下，除非用户明确指定；
12. 日志不得输出 token、API key。

---

## 20. 测试要求

### 20.1 单元测试

必须覆盖：

1. URL 类型识别；
2. zip 安全解压；
3. 项目类型识别；
4. Python 依赖解析；
5. JS 依赖解析；
6. YAML 规则加载；
7. 规则匹配；
8. finding 去重；
9. SQLite 初始化；
10. 报告生成。

### 20.2 集成测试

准备 fixtures：

```text
fixtures/
├── python_safe_skill/
├── python_vulnerable_skill/
├── python_malicious_setup/
├── js_safe_skill/
├── js_vulnerable_skill/
├── js_postinstall_risk/
├── mcp_prompt_injection/
├── mcp_command_tool/
└── mixed_python_js_skill/
```

### 20.3 CLI 测试示例

```bash
sca-cli init --force
sca-cli doctor
sca-cli scan tests/fixtures/python_safe_skill --report
sca-cli scan tests/fixtures/js_postinstall_risk --rules --report
sca-cli intel report --range 24h
```

---

## 21. 验收标准

### 21.1 基础验收

1. Windows 本地可安装；
2. `sca-cli --help` 正常；
3. `sca-cli init` 能创建数据库和目录；
4. `sca-cli doctor` 能检查工具状态；
5. 能扫描本地目录；
6. 能扫描 zip 包；
7. 能扫描 Git URL；
8. 默认生成 SBOM；
9. `--vuln` 能调用可用漏洞扫描器；
10. `--report` 能输出 HTML/MD/JSON。

### 21.2 Agent Skill 验收

1. 能识别 Python Skill；
2. 能识别 JS Skill；
3. 能识别 MCP Server；
4. 能识别 AI Plugin manifest；
5. 能扫描 Tool description 投毒；
6. 能扫描任意命令参数；
7. 能扫描任意 URL / path 参数；
8. 能扫描 Python setup.py 风险；
9. 能扫描 npm postinstall 风险；
10. 能扫描 Python/JS 高危 API。

### 21.3 情报同步验收

1. 能同步 OSV；
2. 能同步 GHSA；
3. 能同步 NVD，允许未配置 API key 但提示限速；
4. 能同步 SPDX；
5. 能同步或导入 AI-Infra-Guard 规则；
6. 能记录同步状态；
7. 能生成 24h 威胁情报报告；
8. 能离线导出/导入数据包。

---

## 22. 第一阶段开发任务清单

### 22.1 P0 必须完成

1. Python 项目骨架；
2. Typer CLI；
3. SQLite 初始化；
4. config.yaml；
5. scan 命令；
6. URL / zip / 目录输入处理；
7. Syft SBOM 生成；
8. Grype 扫描；
9. pip-audit 扫描；
10. npm audit 扫描；
11. 内置规则引擎；
12. Skill/MCP 元数据扫描；
13. 安装脚本风险扫描；
14. 高危 API 扫描；
15. findings 归一化；
16. HTML/MD/JSON 报告；
17. doctor 命令。

### 22.2 P1 建议完成

1. OSV 同步；
2. GHSA 同步；
3. NVD 同步；
4. SPDX 同步；
5. AI-Infra-Guard 规则导入；
6. intel report；
7. 离线导入导出；
8. 规则校验命令；
9. 测试 fixtures。

### 22.3 P2 后续增强

1. ScanCode 许可证扫描；
2. Typosquatting 检测；
3. 恶意包情报库；
4. Python AST 深度扫描；
5. JS AST 深度扫描；
6. OpenAPI 风险扫描增强；
7. SARIF 输出；
8. PDF 报告；
9. CI/CD 模式；
10. Web UI。

---

## 23. 推荐命令输出示例

### 23.1 scan 摘要

```text
Scan completed: agent-weather-skill

Target: ./agent-weather-skill
Type: Python + MCP
Scan ID: 20260611-153012-a8f3

Summary:
  Components: 42
  Vulnerabilities: 5
  Skill Risks: 3
  Install Script Risks: 1
  High Risk API Hits: 4

Risk Level: HIGH

Reports:
  HTML: ~/.sca-cli/reports/20260611-153012-a8f3/report.html
  Markdown: ~/.sca-cli/reports/20260611-153012-a8f3/report.md
  JSON: ~/.sca-cli/reports/20260611-153012-a8f3/report.json
```

### 23.2 intel report 摘要

```text
Threat intelligence report generated

Range: last 24h
Ecosystems: pypi,npm
New vulnerabilities: 36
Critical: 3
High: 12
Agent-relevant packages: 8

Report:
  ~/.sca-cli/reports/intel-20260611/report.html
```

---

## 24. 与传统 SCA v1 的差异

v2 相比 v1 的核心变化：

| 项目 | v1 | v2 |
|---|---|---|
| 产品定位 | 通用 SCA CLI | Agent Skill 供应链扫描 CLI |
| 重点生态 | 多生态通用 | Python / JS 优先 |
| 主风险 | 依赖漏洞 / 许可证 | 依赖漏洞 + Skill 元数据 + 安装脚本 + 高危 API |
| Dependency-Check | 可考虑 | 降级为可选 Java 扩展 |
| pip-audit | 可选 | Python 专项核心 |
| npm audit | 可选 | JS 专项核心 |
| AIG | 补充 | AI/MCP 专项规则源 |
| 报告 | SCA 报告 | Agent Skill 安全报告 |

---

## 25. 参考资料

开发时可参考以下项目和标准：

1. Syft：SBOM 生成工具，支持容器镜像和文件系统；
2. Grype：漏洞扫描器，可扫描 SBOM、镜像和文件系统；
3. pip-audit：Python 包漏洞扫描工具；
4. npm audit：Node.js 依赖漏洞审计命令；
5. OSV：开源漏洞数据库；
6. GitHub Advisory Database：GitHub 生态安全公告；
7. NVD：CVE/CVSS/CWE/CPE 基础漏洞数据；
8. SPDX License List：标准许可证列表；
9. CycloneDX：SBOM 格式；
10. Tencent AI-Infra-Guard：AI Infra / MCP 安全规则参考。

---

## 26. 最终实现目标

Codex 根据本文档应实现一个可以本地运行的 `sca-cli`，具备以下能力：

```text
1. 支持 url / zip / 目录输入；
2. 支持 Python / JS / MCP / Plugin 类型识别；
3. 默认生成 SBOM；
4. 可选漏洞扫描；
5. 支持 pip-audit / npm audit / Grype；
6. 支持 Skill / MCP / Plugin 元数据规则扫描；
7. 支持安装脚本风险扫描；
8. 支持高危 API 扫描；
9. 支持开源漏洞库和规则库同步；
10. 支持本地 SQLite 存储；
11. 支持企业级扫描报告；
12. 支持威胁情报报告；
13. 首发 Windows 可运行；
14. 代码跨平台；
15. 后续可扩展为 Web 平台。
```

本版本的核心产品方向是：

```text
Agent Skill Supply Chain Security Scanner
```

而不是传统意义上的通用 SCA Scanner。

