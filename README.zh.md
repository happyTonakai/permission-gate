# Permission Gate

[![CI](https://github.com/happyTonakai/permission-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/happyTonakai/permission-gate/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/happyTonakai/permission-gate)](https://github.com/happyTonakai/permission-gate/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/happyTonakai/permission-gate)](https://go.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/happyTonakai/permission-gate)](https://goreportcard.com/report/github.com/happyTonakai/permission-gate)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](https://github.com/happyTonakai/permission-gate)
[![License](https://img.shields.io/github/license/happyTonakai/permission-gate)](LICENSE)

> [English README](README.md) · **中文**

基于 AST 的 Shell 命令权限门控。将 Shell 命令解析为 AST，然后对每个命令片段进行三层（允许/拒绝/询问）规则评估。

基于 [`mvdan.cc/sh/v3`](https://github.com/mvdan/sh) 进行 Shell 语法解析。

---

## 工作原理

```
用户输入 → mvdan/sh AST → 命令提取 → 规则匹配 → 裁决
```

每个命令都会被分词并对照三个列表进行检查：

| 层级   | 行为           |
| ------ | -------------- |
| Allow  | 自动放行       |
| Deny   | 自动阻止       |
| Ask    | 提示用户确认   |

如果命令不匹配任何列表，默认行为为 **Ask**（安全优先）。

对于复合命令（管道、`&&`、`||`、子 Shell、`if`/`for`/`while`），每个片段会独立评估。最严格的裁决胜出：一个 deny 就会让整个命令被拒绝。

### 标志级拒绝

除了整条命令的规则，还可以对安全命令上的危险标志进行限制：

```toml
[deny]
flags = { find = ["-exec", "-delete"] }
```

这样 `find . -name '*.go'` 可以放行，但 `find . -exec rm {} \;` 会被阻止。

---

## 安装

### 一键安装（推荐）

自动检测操作系统和架构，从 GitHub Releases 下载最新二进制：

```bash
curl -sSfL https://raw.githubusercontent.com/happyTonakai/permission-gate/main/install.sh | sh
```

安装指定版本：

```bash
curl -sSfL https://raw.githubusercontent.com/happyTonakai/permission-gate/main/install.sh | VERSION=v1.0.0 sh
```

安装到自定义路径（默认 `~/.local/bin/pgate`）：

```bash
curl -sSfL https://raw.githubusercontent.com/happyTonakai/permission-gate/main/install.sh | INSTALL_DIR=/usr/local/bin sh
```

验证：

```bash
pgate version
# permission-gate v1.0.0
```

### 从源码编译

需要 Go 1.25+。

```bash
git clone https://github.com/happytonakai/permission-gate.git
cd permission-gate
go build -o pgate ./cmd/pgate
cp pgate ~/.local/bin/    # 或放到 $PATH 中的任意目录
```

### 安装 Agent 钩子

`pgate` 为三个 AI 编程助手提供了钩子：

```bash
pgate hook install claude      # 写入 ~/.claude/hooks/permission-gate.sh + 注册到 settings.json
pgate hook install opencode    # 写入 ~/.config/opencode/plugins/permission-gate.ts
pgate hook install pi          # 写入 ~/.pi/agent/extensions/permission-gate/index.ts
```

卸载：

```bash
pgate hook uninstall claude
pgate hook uninstall opencode
pgate hook uninstall pi
```

安装后请**重启你的 AI 编程助手**以使钩子生效。

---

## 使用方式

### 检查命令

```bash
pgate check "rm -rf /"
# → deny: denied by pattern "rm"

pgate check "ls -la"
# → allow: allowed by pattern "ls"

pgate check "git push origin main"
# → ask: ask by pattern "git push"
```

### JSON 输出

```bash
pgate check --json "echo hello | grep world" | jq
```

```json
{
  "raw_command": "echo hello | grep world",
  "segments": [
    { "command": "echo hello",  "tokens": ["echo","hello"],
      "verdict": {"level":0,"reason":"builtin allow: echo","matched":"echo"} },
    { "command": "grep world",  "tokens": ["grep","world"],
      "verdict": {"level":0,"reason":"builtin allow: grep","matched":"grep"} }
  ],
  "final": { "level": 0, "reason": "all commands are allowed", "matched": "" }
}
```

`level`：`0` = 允许，`1` = 拒绝，`2` = 询问。

### 从 stdin 读取命令

当没有提供位置参数时，`pgate check` 从 stdin 读取命令。这是 Agent 扩展调用它的方式（这样多行命令和 `for`/`while`/`if` 块能完整保留）：

```bash
echo "rm -rf /" | pgate check
```

### 初始化配置

```bash
pgate init
# 创建 ~/.config/permission-gate/config.toml（如果已存在则无操作）
```

### 自更新

`pgate` 可以直接把自己替换为最新的 GitHub Release，无需另外下载：

```bash
pgate update              # 升级到最新
pgate update --to v1.2.3  # 指定版本（v 前缀可选）
pgate update --force      # 即使已是该版本也强制重新下载
```

已是请求中的版本时，会打印 `"Already on latest version vX.Y.Z"` 并以退出码 0 退出，可以安全地接入脚本。

更新流程：

1. `GET /repos/happyTonakai/permission-gate/releases/latest`（使用 `--to` 时改为 `/releases/tags/<tag>`）
2. 下载对应 Release 中的 `pgate_{OS}_{ARCH}` 资产
3. 校验字节流像可执行文件（ELF / Mach-O magic number）
4. 写入当前二进制旁边的临时文件，`fsync` 后通过 `os.Rename` 原子替换

如果 `pgate` 是从源码构建（未使用 `-ldflags "-X main.version=..."` 注入版本号），`version` 包变量会是 `"dev"`，自更新会拒绝并提示改用 `go install @latest`。原地替换二进制不会影响已安装的钩子——OpenCode / pi 插件通过 `PATH` 查找 `pgate`，Claude 钩子通过安装时写入的绝对路径调用，原地重命名保留了这个路径。

---

## 配置文件

### 文件位置

| 文件                                                | 作用范围                   |
| --------------------------------------------------- | -------------------------- |
| `~/.config/permission-gate/config.toml`             | 全局 — 适用于所有项目      |
| `<cwd>/.permission-gate.toml`                       | 项目 — 仅适用于当前目录    |

环境变量覆盖：

| 变量                              | 覆盖内容            |
| --------------------------------- | ------------------- |
| `PERMISSION_GATE_CONFIG`          | 全局配置文件路径     |
| `PERMISSION_GATE_PROJECT_CONFIG`  | 项目配置文件路径     |

配置文件在每次 `pgate check` 调用时**重新读取**。没有守护进程、没有缓存、没有重载信号——编辑文件后，Agent 的下一个命令就会使用新规则。

### 配置结构

```toml
# .permission-gate.toml
merge_mode = "prepend"   # "prepend"（默认）| "append" | "overwrite"

[allow]   # 自动放行
[deny]    # 自动阻止
[ask]     # 提示用户
```

### 命令规则

每条规则可以是纯字符串（前缀匹配）或带筛选条件的内联表格：

```toml
[allow]
commands = [
  "rg",                                          # 纯字符串：前缀匹配
  { cmd = "rm", include_flags = ["-f","-rf"],     # 仅 /tmp 下的 rm 才放行
    include_args = ["/tmp"] },
]
```

筛选字段：

| 字段            | 含义                                                     |
| --------------- | -------------------------------------------------------- |
| `cmd`           | 前缀匹配命令的开头部分（必填）                             |
| `include_flags` | 命令必须包含至少一个这些标志（任意匹配）                   |
| `exclude_flags` | 命令不能包含任何这些标志（排除匹配）                       |
| `include_args`  | 每个非标志参数必须以这些前缀之一开头（全匹配）              |
| `exclude_args`  | 不能有任何非标志参数以这些前缀开头（排除匹配）              |

### 合并模式

项目配置 + 全局配置 + 内置规则可以叠加：

| 模式        | 顺序                         | 效果                                               |
| ----------- | ---------------------------- | -------------------------------------------------- |
| `prepend`   | 用户规则 → 内置规则          | 用户可以覆盖内置规则（小心使用）                    |
| `append`    | 内置规则 → 用户规则          | 内置规则优先级更高                                 |
| `overwrite` | 仅用户规则                   | 内置规则和全局规则都被忽略，仅使用项目配置文件      |

---

## 内置规则

Permission Gate 内置了约 10,000 条安全命令模式，涵盖：

- **文件操作**：`ls`、`cat`、`echo`、`find`、`grep`、`head`、`tail`
- **版本控制**：`git log`、`git status`、`git diff`（只读），`git push`（Ask）
- **开发工具**：`go build`、`npm install`、`pip`、`cargo`、`docker ps`
- **系统命令**：`uname`、`df`、`du`、`ps`、`uptime`

用户配置可以通过合并模式覆盖任何内置规则。

### 内置危险标志规则

为防止安全命令被滥用，以下危险标志默认被拒绝：

| 命令      | 拒绝的标志集                                                                  |
| --------- | ----------------------------------------------------------------------------- |
| `find`    | `-exec`, `-execdir`, `-delete`, `-ok`, `-okdir`                               |
| `sed`     | `-i`, `--in-place`                                                            |
| `tar`     | `--to-command`, `-I`, `--use-compress-program`, `--checkpoint-action`          |
| `curl`    | `--output`, `-o`, `--remote-name`, `-O`, `--upload-file`, `-T`                |
| `wget`    | `-O`, `--output-document`, `-o`, `--output-file`                              |
| `dd`      | `if=`, `of=`                                                                  |
| `docker`  | `exec`, `-it`, `--interactive`, `--tty`                                       |
| `kill`    | `-9`, `--signal`                                                              |
| `python`  | `-c`                                                                          |
| `chmod`   | `-R`, `--recursive`                                                           |
| `chown`   | `-R`, `--recursive`                                                           |

---

## 架构

```
cmd/pgate/                  # CLI 入口
  main.go                   # check / init / hook / version 子命令
  hooks.go                  # Claude / OpenCode / pi 钩子安装器

internal/
  verdict/verdict.go        # 核心类型（Allow / Deny / Ask）
  analyze/analyze.go        # 基于 AST 的命令提取
  rules/engine.go           # 规则匹配引擎
  config/config.go          # TOML 配置加载与合并
  builtin/
    commands.go             # 约 400 条手工精选命令
    generated_commands.go   # 约 9,785 条自动生成规则
    cmd/convert.go          # TOML → Go 代码生成器
```

---

## 许可协议

MIT
