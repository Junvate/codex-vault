# Codex Vault v0.1.0 Linux 验证报告

## 结论

验证日期基准：**2026-09-10**

固定版本 v0.1.0 / 7e72748c4d8242a8179e21448b8873025c1c5a6d 在本机完成构建、测试、依赖审计和要求的 Linux 隔离场景验证。除项目明确声明的同 UID、root 和 SIGKILL 边界外，本轮要求的行为均符合预期，没有观察到测试明文残留或密文篡改后被接受。

本结论**不是安全审计结论，也不表示项目“绝对安全”**。v0.1.0 仍不适合把共享同一 Unix UID 的敌对用户相互隔离，也不能防御 root、内核、宿主机控制权或强制终止后的明文取证。

建议进入 v0.2 开发，但不建议把 v0.1.0 作为敌对多用户或高敏感生产环境的唯一安全控制。

## 验证范围与方法

- 使用普通用户 xmu（UID/GID 1000），未使用 root。
- 使用权限为 0700 的一次性测试根目录；Vault、运行目录和破坏性副本均位于该目录。
- 未使用真实 OpenAI Token、Codex 登录状态、API Key 或历史会话。
- mock Codex 使用绝对路径，通过 CODEX_VAULT_REAL_CODEX 指定，只处理虚构标记。
- mock 支持写入/读取标记、输出 CODEX_HOME/CODEX_VAULT_ACTIVE_USER，以及睡眠 60 秒。
- bit-flip、截断、尾部追加和锁文件符号链接测试均基于 cp -a 创建的独立 Vault 副本。
- 用户要求改为自动验证后，驱动在进程内生成一次性随机密码，经伪终端送入原生隐藏提示；密码值未进入命令行、环境变量、脚本、终端输出、日志或报告，驱动退出前覆盖其可控缓冲区。
- 测试结束后，SIGKILL 遗留明文目录立即删除；报告生成后删除最终测试 Vault、密文副本、证据目录和验证驱动。
- 未修改 src/、tests/、Cargo 配置或其他项目源文件，未提交、未推送。

## 环境

| 项目 | 值 |
|---|---|
| 发行版 | Ubuntu 22.04.5 LTS (Jammy Jellyfish) |
| 内核 | Linux 5.15.0-91-generic |
| 架构 | x86_64，little-endian |
| CPU | Intel Xeon Silver 4314 @ 2.40 GHz，64 个在线逻辑 CPU |
| 当前身份 | uid=1000(xmu) gid=1000(xmu) |
| 工作区文件系统 | /data -> /dev/sdc，ext4，rw,relatime,stripe=192 |
| XDG_RUNTIME_DIR | 未设置 |
| /dev/shm | tmpfs，rw,nosuid,nodev,inode64 |
| Rust | rustc 1.98.1 (48a229cea 2026-09-01) |
| Cargo | cargo 1.98.1 (797e8a9bc 2026-08-05) |
| cargo-audit | 0.22.2 |
| Codex Vault | codex-vault 0.1.0 |
| 已安装 Codex | codex-cli 0.153.4 |

系统原先没有 Rust/Cargo。按照仓库 rust-toolchain.toml，通过 Rust 官方 rustup 安装 1.98.1 minimal profile 到一次性验证目录，并安装 rustfmt、clippy 和 cargo-audit；未更改系统安全配置。

## 固定版本验证

状态：**PASS**

直连 github.com:443 在测试机网络中超时，因此 Git 对象通过只读 HTTPS 代理克隆；随后使用直连 GitHub API 验证 annotated tag 指向，并用直连 codeload.github.com tag 归档逐文件交叉比对。代理不是信任锚，信任依据是用户给定的完整 commit 哈希和两条独立 GitHub 读取路径的一致性。

~~~text
$ git rev-parse 'v0.1.0^{commit}'
7e72748c4d8242a8179e21448b8873025c1c5a6d

$ git rev-parse HEAD
7e72748c4d8242a8179e21448b8873025c1c5a6d
~~~

- 目标哈希完全匹配。
- GitHub API 的 tag 对象 70d2d432544c8616b8851543cffa8d11c46bdbf5 指向该 commit。
- codeload 归档 SHA-256：be6c7c8ceac2fc9952a49f9ae5a9efa026008fc9baa65ec8464666c1f8514d48。
- 构建前，归档与检出内容逐文件无差异；构建后唯一额外目录为被 Git 忽略的 target/。
- git tag -v v0.1.0 返回 error: no signature found。因此 commit 身份验证为 PASS，但发布者签名来源保证为 **PARTIAL**。

## 文档审阅

已完整阅读 README.md、SECURITY.md、docs/THREAT_MODEL.md 和 docs/ARCHITECTURE.md。

文档明确声明 v0.1.0 只提供登出后静态加密与应用级用户隔离，不构成同 UID 敌对用户之间的进程隔离；root 和不可捕获的强制终止也在范围外。相关声明见 [SECURITY.md](../SECURITY.md#L3)、[SECURITY.md](../SECURITY.md#L11) 和 [docs/THREAT_MODEL.md](../docs/THREAT_MODEL.md#L21)。

## 构建与依赖验证

| 命令 | 状态 | 必要输出 |
|---|---|---|
| cargo fmt -- --check | PASS | 退出码 0，无格式差异 |
| cargo clippy --all-targets --all-features --locked -- -D warnings | PASS | Finished dev profile，零 warning |
| cargo test --all-targets --all-features --locked | PASS | 10 passed，0 failed，0 ignored |
| cargo build --release --locked | PASS | Finished release profile [optimized] |
| cargo audit | PASS | 加载 1243 条 advisory，扫描 Cargo.lock 中 96 个依赖，退出码 0，无已知漏洞报告 |

测试分布：

~~~text
src/lib.rs:        2 passed
src/main.rs:       0 tests
tests/runner.rs:   1 passed
tests/store.rs:    7 passed
total:            10 passed, 0 failed
~~~

cargo audit 结果只代表 2026-09-10 当时 RustSec 数据库中没有匹配项，不证明依赖不存在未知漏洞。

## 隔离测试结果

| # | 场景 | 状态 | 证据摘要 |
|---:|---|---|---|
| 1 | codex-vault init | PASS | 退出码 0，Vault 根目录 0700 |
| 2 | 创建 Alice 和 Bob | PASS | 两个用户均通过隐藏提示创建 |
| 3 | user list | PASS | 按序输出 alice、bob |
| 4 | Alice 写入后 Bob 读取 | PASS | Bob 的 CODEX_HOME 中不存在 Alice 标记 |
| 5 | Alice 再次读取 | PASS | Alice 成功读取自己的虚构标记 |
| 6 | 错误密码 | PASS | 返回 invalid username or password，运行根目录保持为空 |
| 7 | 静态明文扫描 | PASS | Alice/Bob 的 state.cvlt 和 manifest.json 均不含测试标记 |
| 8 | 文件权限 | PASS | Vault/users/用户目录为 0700；manifest、密文、锁文件为 0600 |
| 9 | 用户目录改为 0755 | PASS | 解锁被拒绝；测试后恢复为 0700 |
| 10 | Alice 并发重入 | PASS | 第二次解锁返回 this user vault is already unlocked |
| 11 | Alice 活动时 Bob 运行 | PASS | Bob 使用独立运行目录成功执行 mock |
| 12a | 密文单字节翻转 | PASS | 返回 encrypted vault authentication failed；无部分运行目录 |
| 12b | 密文截断 1 字节 | PASS | 返回 encrypted vault is truncated；无部分运行目录 |
| 12c | 密文追加 1 字节 | PASS | 返回 encrypted vault has trailing data；无部分运行目录 |
| 13 | active.lock 符号链接 | PASS | 返回 Too many levels of symbolic links，目标内容未改变 |
| 14 | SIGTERM | PASS | 子进程收到信号，启动器退出码 143，状态重新加密，运行目录删除，再次解锁可读取信号前标记 |
| 15 | SIGKILL | EXPECTED-LIMITATION | 启动器退出码 137，遗留 0700 的明文 codex-home；取证后删除 |
| 16 | 同 UID 读取 | EXPECTED-LIMITATION | Alice 解锁期间，另一个 UID 1000 进程成功读取其测试标记 |
| 17 | Linux 默认运行目录 | PASS | XDG_RUNTIME_DIR 未设置时选择 /dev/shm/codex-vault-1000/...，底层为 tmpfs；正常退出后会话目录删除 |
| 18 | 真实 codex --version | PASS | 仅通过 Vault 执行一次，输出 codex-cli 0.153.4；未登录或打开真实会话 |
| - | root 边界 | EXPECTED-LIMITATION | root 可读取解锁数据；按威胁模型记录，本轮未提升权限实测 |
| - | 最终明文清理 | PASS | 显式 runtime 为空；默认 tmpfs 会话目录不存在；无 Vault/mock 残留进程 |

权限抽样：

~~~text
700 <TEST_ROOT>
700 <TEST_ROOT>/vault
700 <TEST_ROOT>/vault/users
700 <TEST_ROOT>/vault/users/alice
700 <TEST_ROOT>/vault/users/bob
600 <TEST_ROOT>/vault/users/alice/manifest.json
600 <TEST_ROOT>/vault/users/alice/state.cvlt
600 <TEST_ROOT>/vault/users/alice/active.lock
~~~

密文副本大小证据（原始 Alice state.cvlt 为 3142 字节）：

~~~text
bitflip   3142
truncate  3141
append    3143
~~~

默认运行目录证据：

~~~text
/dev/shm tmpfs tmpfs rw,nosuid,nodev,inode64
~~~

## 安全发现与边界

### HIGH（超出 v0.1 保证）：同 UID 可读取解锁明文

状态：**EXPECTED-LIMITATION**

复现：

1. 让 Alice 通过 Vault 保持运行。
2. 用同一 Unix UID 启动另一个进程。
3. 读取 Alice 运行目录中 CODEX_HOME/sessions/owner.txt。
4. 本轮读取成功。

原因是进程和文件仍归同一 UID；CODEX_HOME 的 0700 无法隔离同 UID 进程。运行目录创建见 [src/store.rs](../src/store.rs#L160)，环境注入见 [src/runner.rs](../src/runner.rs#L43)。这与 [SECURITY.md](../SECURITY.md#L11) 的声明一致。

### HIGH（超出 v0.1 保证）：SIGKILL 可遗留明文

状态：**EXPECTED-LIMITATION**

复现：

1. Alice 解锁并在 CODEX_HOME 写入纯测试标记。
2. 对 codex-vault 启动器发送 SIGKILL。
3. 启动器退出码为 137。
4. CODEX_VAULT_RUNTIME_DIR/<id>/codex-home 仍存在，测试标记可读。

SIGKILL 无法被捕获；正常重新加密和 TempDir 删除只发生在等待子进程结束后的关闭路径，[src/runner.rs](../src/runner.rs#L70)、[src/store.rs](../src/store.rs#L228)。信号转发器只注册 SIGINT、SIGTERM 和 SIGHUP，[src/runner.rs](../src/runner.rs#L99)。该限制已在 [SECURITY.md](../SECURITY.md#L13) 声明。

### CRITICAL 影响 / 非漏洞评级：root 与宿主机控制权

状态：**EXPECTED-LIMITATION**

root、内核、hypervisor 或被攻陷宿主可读取已解锁数据和进程内密钥。本轮坚持普通用户测试，未通过提权重复读取。该边界见 [SECURITY.md](../SECURITY.md#L12) 和 [docs/THREAT_MODEL.md](../docs/THREAT_MODEL.md#L31)。

### MEDIUM（供应链残余风险）：v0.1.0 tag 未签名

状态：**PARTIAL**

固定 commit 哈希、GitHub API 和 codeload 内容均一致，足以确认验证了用户指定对象；但 git tag -v 明确返回无签名，无法建立发布者密码学身份链。建议 v0.2 使用签名 tag，并发布可验证的 source archive checksum/SBOM。

### LOW（可观测性）：密文完整性错误被显示为通用 I/O 错误

状态：**PARTIAL**

三种破坏均被正确拒绝，因此不影响本轮完整性安全结果；但 CLI 输出前缀是 I/O error:，而不是 vault integrity verification failed:。复现是在三个独立 cp -a 副本上分别翻转、截断和追加，再用正确密码解锁。帧读取把完整性失败构造成 io::Error，[src/crypto/vault_stream.rs](../src/crypto/vault_stream.rs#L209)，经 archive 的问号运算符传播，[src/archive.rs](../src/archive.rs#L53)。建议在边界处映射为 VaultError::Integrity，便于告警和自动化分类。

## 未覆盖项目

- 未执行 root、内核、hypervisor、DMA、冷启动或物理内存攻击。
- 未模拟断电、内核 panic、磁盘满、I/O 错误或文件系统崩溃；仅验证 SIGTERM 与 SIGKILL。
- 未单独构造“完整认证帧重排”样本；源码检查显示序号校验位于 [src/crypto/vault_stream.rs](../src/crypto/vault_stream.rs#L218)，但应补充端到端回归测试。
- 未构造带有效认证、但包含路径穿越项的恶意归档；源码使用 unpack_in 并拒绝越界，见 [src/archive.rs](../src/archive.rs#L56)，仍建议增加专门测试。
- 未验证密码轮换/数据密钥 rewrap；v0.1 CLI 没有对应命令。
- 未验证 dedicated UID、PAM、daemon、mount namespace、/proc 隔离；这些属于 v0.2 目标。
- 未实现或验证有效旧 Vault 回滚检测；威胁模型明确把 rollback/availability 放在范围外。
- 未验证 Codex 写到 CODEX_HOME 外部的位置、网络层、Node/npm 依赖或真实登录流程。
- 仅覆盖 Ubuntu 22.04.5、ext4 持久存储与 tmpfs runtime；未覆盖 macOS、其他 Linux 发行版/内核和 NFS/CIFS/FUSE。
- 没有独立密码学代码审计、模糊测试、并发压力测试或长期故障注入。

## 残余风险

- 同 UID 和 root 边界使 v0.1.0 不适合敌对共享账号场景。
- SIGKILL、断电或崩溃后，明文可能在运行介质上持续存在，必须依赖启动时清扫或外部运维处置。
- 删除 ext4 上的测试文件不等于可证明的物理介质擦除；本轮没有真实凭据，所有标记均为虚构数据。
- 有效旧密文可回滚，Vault 删除和拒绝服务也不在保护范围。
- Argon2id/AES-GCM 的使用和测试通过不能替代第三方密码学审计。
- 未签名发布 tag 降低了发布工件的来源可验证性。

## v0.2 建议

**建议进入 v0.2 开发。** 优先级如下：

1. 通过 privileged daemon + dedicated UID/container 建立真正的活动期进程隔离。
2. 使用受控 tmpfs/encrypted mount、启动时 stale-runtime 扫描和明确的崩溃恢复流程降低明文遗留风险。
3. 增加帧重排、认证归档路径穿越、stale lock、密码轮换、回滚和故障注入测试。
4. 将完整性错误稳定映射为专用错误类型，并为日志/监控提供机器可读退出分类。
5. 签名 release tag，发布 checksum、SBOM，并安排独立安全与密码学审计。

在以上边界落实前，v0.1.0 可作为静态加密原型继续开发验证，但不应被描述为已通过安全审计。
