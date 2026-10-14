# Kata exec `NoNewPrivileges` 修复

[补丁](0001-fix-runtime-preserve-exec-no-new-privileges.patch)修复 Kata 4.2.0
宿主机 Go runtime 的字段转换：`cmdToKataProcess` 应将
`types.Cmd.NoNewPrivileges` 传给 `grpc.Process.NoNewPrivileges`。
补丁只改转换函数和现有单元测试，guest agent、协议和策略不需要修改。

## 为什么需要

Pod 设置 `allowPrivilegeEscalation: false` 时，官方 `genpolicy` 生成的
Kata agent policy 要求 `Process.NoNewPrivileges=true`。containerd 的 exec
请求已携带这个值，Go runtime 漏传后，guest agent 收到的值变成 false。
原本允许的 exec readiness probe 因而被 policy 拒绝。

```text
containerd OCI process → types.Cmd → grpc.Process → guest kata-agent policy
                                      ↑ 补全 NoNewPrivileges 赋值
```

这里的 policy 是 **Kata guest agent 的 Rego policy**，用于约束宿主机 RPC。
OpenShell supervisor 的应用/网络策略和 Trustee 的证明/密钥释放策略分别在
其他层执行。这个问题丢失的是请求字段，生成的 agent policy 本身没有传坏。

补丁保留调用者的 true/false 值，不强制开启该配置。修复路径与 Alibaba、TDX、
PeerPods 和 OpenShell 无关；Rust runtime 使用另一套实现。

## 基线与检查

部署基线为 Kata 4.2.0：`c7351e797efff8bfc6bd73da0eb1909be12e2cfe`。
来源和补丁结果树见 [源码锁](../../deployment/build/sources.lock.json)。
在干净的 Kata checkout 根目录执行：

```bash
PATCH=/path/to/0001-fix-runtime-preserve-exec-no-new-privileges.patch
git apply --check "$PATCH"

# 只加测试时，true 断言应失败。
git apply --include=src/runtime/virtcontainers/kata_agent_test.go "$PATCH"
(cd src/runtime && go test ./virtcontainers -run '^TestCmdToKataProcess$' -count=1)

# 加入赋值修复后，同一测试应通过。
git apply --include=src/runtime/virtcontainers/kata_agent.go "$PATCH"
(cd src/runtime && go test ./virtcontainers -run '^TestCmdToKataProcess$' -count=1)
git diff --check
gofmt -l src/runtime/virtcontainers/kata_agent.go \
  src/runtime/virtcontainers/kata_agent_test.go
```

单元测试覆盖字段转换。runtime → agent → policy 的独立复现、贡献资料及
[Issue #14024](https://github.com/kata-containers/kata-containers/issues/14024)、
[PR #14025](https://github.com/kata-containers/kata-containers/pull/14025)
见 [上游审阅材料](upstream/README.md)。部署时仍按源码锁应用本地补丁。
