# Kata 上游提交记录

已于 2026-10-12 发布 [Issue #14024](https://github.com/kata-containers/kata-containers/issues/14024)
和 [PR #14025](https://github.com/kata-containers/kata-containers/pull/14025)。已复用账号现有
[fork](https://github.com/wdsun1008/kata-containers)，将一个修复提交推送到
[`fix-exec-no-new-privileges`](https://github.com/wdsun1008/kata-containers/tree/fix-exec-no-new-privileges)。
该分支只改两个上游 Go 文件；此处文档和复现工具不在它的 PR diff 中。

- [Issue 正文](issue.md)：第一行是已发布标题，其余为正文。
- [PR 正文](pr.md)：第一行是已发布标题，其余为正文，关联 `Fixes: #14024`。
- [完整修复提交](https://github.com/wdsun1008/kata-containers/commit/e11d46ae543cfdd4c96d20de40e508e5a955db61)：提交说明、DCO 和 AI trailer 可直接审阅。
- [离线策略复现](reproduce-policy.py)：使用完整上游规则、合成允许探针的 policy 数据及固定创建后状态；不启动 VM。
- [真实请求证据摘要](captured-evidence.json)：已核对原始 protobuf、实际 Pod 和生成策略，只包含命令、布尔值及摘要哈希。
- [真实运行验证](validation.md)：4.2.0 和 PR 的 `main` 基线均完成原版 → 修复版 → 原版对照，包含可复用的 CRI 输入。
- [运行证据摘要](live-evidence.json)：六个真实 VM、36 次 exec 的逐项结果、固定组件哈希和验证范围。

## 贡献指南核对

已读取 [Kata CONTRIBUTING](https://github.com/kata-containers/kata-containers/blob/46c507fe445370f0728aeefbfd16c49cead0493d/CONTRIBUTING.md)、
组织默认 [bug report 模板](https://github.com/kata-containers/.github/blob/main/.github/ISSUE_TEMPLATE/bug_report.md)
和提交格式 CI。分支基于上游 `main` `46c507fe445370f0728aeefbfd16c49cead0493d`；
单提交、单主题，标题带 `runtime:` 且不超过 75 字符，正文行不超过 150 字符。
提交使用已有 Git 身份 `Weidong Sun <sunweidong@linux.alibaba.com>`，包含
`Signed-off-by` 和 `Generated-By: OpenAI Codex`。

经过作者审阅后，按授权创建 issue，再在主修复提交和 PR 正文加入真实的 `Fixes: #14024`。
仅修订提交说明，源码树与已完成实跑验证的提交一致；DCO 和 AI trailer 保留。
PR 为单提交、两个 Go 文件。上游 CI 等待维护者添加 `ok-to-test`；Gatekeeper 当前因缺少
该标签退出，CI 测试被跳过，尚无上游测试结果。

2026-10-12 再次核对：官方最新 release 为 4.2.0，`main` 仍是上述基线；项目及组织默认
仓库均未提供 PR 模板。Issue 已对齐 bug 模板的 Description / Expected / Actual /
Further information 栏目，保留最小复现和对照结果。Issue 标题 62 字符、PR 标题 52 字符，
正文行宽分别不超过 81 / 85 字符；LF、gofmt、差异空白检查通过。
修复提交按官方 commit-message-check 的正则核对了 subsystem、标题、正文，
作者邮箱与 DCO 一致，`Generated-By` 已保留。这是本地规范检查，不代表完整上游 CI 已通过。

主修复提交已包含 `Fixes: #14024`。按 bug 模板发布的
[collector 评论](https://github.com/kata-containers/kata-containers/issues/14024#issuecomment-6119735795)
是直接运行官方脚本的原样 stdout，本地存放于
`.local/kata-community-review-20261012/compliance/issue-collector-comment.md`。已从 GitHub 读回正文，
确认与本地输出逐字节一致。
该文件与 `official-collector.stdout.md` 逐字节一致，真实路径和默认配置查找错误均保留。
隔离测试使用显式 `ConfigPath`，默认 collector 无法自动发现它；另保留官方
`kata-runtime --config <实际配置路径> env` 的原样输出、实际配置文件和测试 containerd 版本。
上述真实输出与配置已发布为
[补充环境评论](https://github.com/kata-containers/kata-containers/issues/14024#issuecomment-6119736468)。
文件及采集说明存于同一目录；配置哈希已与原实跑记录核对。此前的路径占位符和
误改软件包版本的脱敏处理稿已撤回，仅留作审计，不作为待提交材料。
官方关于作者亲自调整文案的建议也仍适用。

搜索了 `NoNewPrivileges`、`no_new_privileges`、`cmdToKataProcess` 及 exec/probe 相关 issue/PR，
未找到这处字段漏传的专门修复。已有 #10648 讨论 containerd 2.0 的容器创建策略适配，
不能拿它替代本问题的 issue 编号。本次发布前已再次检查最新上游状态。

## 验证范围

主要 validation 已补成真实 VM 中的 runtime → agent → policy 验证。采用官方 4.2.0
QEMU、kernel、guest image、agent、genpolicy，以及独立 containerd static 2.3.4；
普通 BusyBox Pod，无 OpenShell、CAA、云服务或定制 guest 依赖。
固定 Pod/CRI 输入、guest、完整生成策略及所有配置，分别在 4.2.0 和 PR `main` 基线上运行：

| 实际观察 | 原版 | 修复版 | 回切原版 |
| --- | --- | --- | --- |
| 容器启动 | 成功 | 成功 | 成功 |
| agent 收到的 exec 字段 | false | true | false |
| 已批准的探针 | policy 拒绝 | exit 0 | policy 拒绝 |
| 错误命令 / UID 0 | 拒绝 | 拒绝 | 拒绝 |

保存了 agent 自带的实际请求日志和经 CRI 返回的拒绝文本；逐一比较对应的 Process 对象，
只有 `NoNewPrivileges` 改变。所有测试容器、sandbox、VM 已清理，独立 containerd 已停止，
共享集群未改动。调试控制台仅在这些隔离测试 VM 中用于读取现有日志，所有探针通过正常
CRI/containerd 路径执行；策略持续生效，负例未获放行。

旧 PeerPods health 抓包/策略回放保留为原始背景证据；它与本轮独立实跑分别说明，
不把旧 Pending/NotReady 快照归因于这个字段，也不把后续多组件部署算作单补丁对照。
新增 Go 断言用于防回归，合成 OPA 用例只作补充。

4.2.0 用 Go 1.26.7，当前 `main` 用其要求的 Go 1.26.8，均验证了仅加测试时失败、加入修复后通过。
当前 `main` 还通过 `go vet ./virtcontainers`、官方 Go shim 构建、gofmt 和差异空白检查。
未运行 kubelet，因此没有测量 Kubernetes Ready/liveness 状态变化，也未重跑云端 TDX/OpenShell
生命周期或整个 `make check`/`make test`、上游跨后端 CI。官方 `kata-collect-data.sh` 和
实际配置/原始日志已保存在 `.local/kata-exec-live-20261012/`；当前官方 collector 原样输出已按作者授权发布到 issue。
issue/PR 正文已直接说明 Kata 侧的最小复现、原版/修复版/回切对比结果；
OpenShell 仅作为一句发现背景。详细日志和 fixture 留作本地验证记录，正文不依赖额外审阅分支。
已发布 PR 的 `fix-exec-no-new-privileges` 分支仍只改两个 Go 文件。

本地策略复现命令（需要已有 OPA 1.18.2 和对应完整 Kata checkout）：

```bash
python3.11 patches/kata-containers/upstream/reproduce-policy.py \
  --kata-source .local/kata-community --opa "$PWD/.local/opa-diagnostic"
```

同一 policy 和容器状态下：已允许探针 + true 为允许；只改为 false、错误命令、UID 0 或额外
`CAP_SYS_ADMIN` 均为拒绝。工具支持已核对的 4.2.0/main 规则哈希，并使用各自的容器状态格式。
