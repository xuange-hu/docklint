# docklint

**同时读三个文件的容器构建审计器。**

绝大多数 Dockerfile linter 只读一个文件。真正昂贵的错误，往往藏在三个文件的缝隙里：Dockerfile、`docker-compose.yml`、`.dockerignore`。

```console
$ docklint scan .
Dockerfile
   6  DRL008  high     supply-chain
        | RUN curl -fsSL https://example.com/install.sh | sh
        -> a downloaded script is piped directly into an interpreter
        fix: Download, verify a checksum or signature, then execute the local file.
  11  DRX001  high     build-integrity
        | COPY data/fixture.json /app/fixture.json
        -> `data/fixture.json` is excluded by .dockerignore, so COPY cannot find it

summary: 2 critical, 16 high, 8 medium, 17 low, 10 info  worst=critical  risk=100/100
```

零依赖、不联网、Python 3.10+。38 条规则、三遍扫描、原生 SARIF。

```console
# 当前可用的安装路径（PyPI 发布待开通）
uvx --from "git+https://github.com/xuange-hu/docklint" docklint demo
uvx --from "git+https://github.com/xuange-hu/docklint" docklint scan .
```

---

## 为什么是三遍

| 第几遍 | 读什么 | 回答什么 |
|---|---|---|
| 1 | `Dockerfile` | 镜像里装进了什么 |
| 2 | `docker-compose.yml` | 部署时授予了什么 |
| 3 | 三个文件一起 | 它们互相是否对得上 |

第三遍才是这个工具的存在理由。下面三个例子，单文件看都"没问题"：

**1. 注定失败的 COPY**

```dockerfile
COPY data/fixture.json /app/       # Dockerfile 合法
```

```gitignore
data/                               # .dockerignore 把它排除了
```

构建会在拉完基础镜像、跑了几分钟之后报 `COPY failed: file not found`。两个文件各自都没错。→ `DRX001`

**2. 被撤销的降权**

```dockerfile
USER 10001                          # 镜像是对的
```

```yaml
user: root                          # compose 又改回 root
```

评审看的是 Dockerfile，线上跑的是 uid 0。→ `DRX006`

**3. 永远留在 layer 里的密钥**

```dockerfile
COPY id_rsa /app/id_rsa             # 烤进镜像
```

```yaml
volumes: ["./id_rsa:/app/id_rsa:ro"] # 运行时挂载盖住它
```

挂载让烤进去的那份"看不见"，所以没人发现它仍然可以被 `docker pull` 下来。→ `DRX004`

## 三步跑通

```console
$ git clone https://github.com/xuange-hu/docklint && cd docklint
$ pip install -e .
$ docklint demo                # 内置一个故意写坏的项目，38 条规则全命中
$ docklint scan path/to/project
```

退出码：`0` 干净或未达门禁，`1` 触发门禁，`2` 用法错误。

```console
$ docklint scan . --fail-on high            # 默认门禁
$ docklint scan . --format json -o out.json
$ docklint scan . --format sarif -o docklint.sarif
$ docklint scan . --ignore DRL011 --ignore-group hygiene
$ docklint rules --pass 3                   # 只看跨文件那一遍能发现什么
```

## GitHub Actions

```yaml
- name: Audit container build files
  run: |
    pip install "git+https://github.com/xuange-hu/docklint"
    docklint scan . --fail-on high --format sarif -o docklint.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: docklint.sarif
```

## MCP 服务（Claude Code / Cursor / Cline）

```json
{
  "mcpServers": {
    "docklint": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/xuange-hu/docklint[mcp]", "docklint-mcp"]
    }
  }
}
```

7 个工具：`docklint_scan`、`docklint_explain`、`docklint_rules`、`docklint_sarif`、
`docklint_dockerfile`（阶段/COPY/USER 结构摘要）、`docklint_compose`（服务图）、`docklint_demo`。

## 规则总览

### 第 1 遍 · Dockerfile（20 条）

| ID | 级别 | 抓什么 |
|---|---|---|
| DRL001 | medium | `FROM` 无 tag，等于 `:latest` |
| DRL002 | low | `FROM ...:latest` |
| DRL003 | high | 运行阶段没有降权（无 `USER` 或 `USER root`） |
| DRL004 | low | 该用 `COPY` 却用 `ADD`（ADD 还会解包） |
| DRL005 | high | `ADD https://...` 构建期无校验下载 |
| DRL006 | high | `COPY`/`ADD` 了 `id_rsa`、`.ssh`、`.env`、`*.pem`、`credentials` |
| DRL007 | medium | `RUN` 里用 `sudo` |
| DRL008 | high | `curl ... \| sh`，远端脚本以 root 执行 |
| DRL009 | low | `apt-get install` 缺 `--no-install-recommends` |
| DRL010 | low | 同一个 `RUN` 里没清 apt 索引 |
| DRL011 | low | `pip install` 缺 `--no-cache-dir` |
| DRL012 | high | `ENV PASSWORD=...`，`docker inspect` 可见 |
| DRL013 | high | `ARG SECRET=...`，`docker history` 可见 |
| DRL014 | low | 对外服务却没有 `HEALTHCHECK` |
| DRL015 | low | `EXPOSE` 了 1024 以下的端口 |
| DRL016 | medium | `ONBUILD`，子镜像里藏着看不见的指令 |
| DRL017 | high | `rm -rf $VAR/`，变量为空时变成 `rm -rf /` |
| DRL018 | low | `CMD` 用 shell form（不是 PID 1，收不到 SIGTERM） |
| DRL019 | medium | `ENTRYPOINT` 用 shell form |
| DRL020 | high | `COPY --from=<stage>` 指向不存在的阶段 |

### 第 2 遍 · compose（12 条）

| ID | 级别 | 抓什么 |
|---|---|---|
| DRC001 | critical | `privileged: true` |
| DRC002 | high | `network_mode: host` |
| DRC003 | high | `pid/ipc/uts: host` |
| DRC004 | critical | 挂载 `/var/run/docker.sock`、`/etc`、`/root`、`/proc`、`/sys`、`/dev` |
| DRC005 | high | `cap_add: SYS_ADMIN`、`SYS_PTRACE`、`NET_ADMIN`、`ALL` 等 |
| DRC006 | low | 没设 `no-new-privileges` |
| DRC007 | high | `environment` 里写死密钥 |
| DRC008 | medium | 端口发布到 `0.0.0.0` 而不是回环 |
| DRC009 | low | 镜像 tag 浮动 |
| DRC010 | info | 根文件系统可写 |
| DRC011 | info | 没配 restart 策略 |
| DRC012 | medium | `env_file` 指向不存在的文件 |

### 第 3 遍 · 跨文件关系（6 条）

| ID | 级别 | 抓什么 |
|---|---|---|
| DRX001 | high | `COPY` 的源被 `.dockerignore` 排除，构建必失败 |
| DRX002 | high | compose 的 `build.dockerfile` 磁盘上不存在 |
| DRX003 | high | 两个服务（或 base + override）抢同一个宿主端口 |
| DRX004 | high | 密钥既烤进 layer 又被运行时挂载覆盖 |
| DRX005 | medium | `COPY .` 而 `.git` 仍在构建上下文里 |
| DRX006 | high | compose 用 `user: root` 覆盖了已降权的镜像 |

## 设计取舍

**证据，不是意见。** 每条 finding 都带 `path:line` 和原始行。手工复核不了的结论只是传闻。

**手写解析器。** Dockerfile 解析器在续行和 heredoc 上保留行号（`RUN <<EOF` 里的 `FROM` 不能凭空造出一个阶段）。compose 解析器是保留逐标量行号的 YAML 子集；遇到锚点会明确提示，而不是悄悄展开错。

**级别说的是后果，不是风格。** `critical` 指宿主机失守（docker socket、privileged）；`info` 指"你可能是有意的"——可写文件系统、没有 restart 策略，很多场景本来如此。

**误报是缺陷。** 每条规则都配反向测试：`rm -rf /var/lib/apt/lists/*` 不是 DRL017，`.env.example` 不是 DRL006，`--from=nginx:1.25` 不是 DRL020，带 `--no-install-recommends` 的 `apt-get install` 不是 DRL009。会叫狼来了的 linter 会被静音，静音的 linter 比没有更糟。

## 开发

```console
$ pip install -e ".[mcp]"
$ python -m pytest -q          # 覆盖率由测试守护
$ docklint scan .              # 狗食：本仓库自扫必须干净
```

## 许可

MIT。
