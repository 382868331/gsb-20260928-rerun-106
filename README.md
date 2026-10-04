# Go 网络流量取证核心

当前版本只读取人工 pcap，不监听真实网卡。核心提供：

- 以太网/IPv4/TCP 解析。
- 四元组和连接代次组成的会话身份。
- 原始报文、乱序、重传、重叠冲突、迟到片段和缺口证据。
- c2s/s2c 双向重组，缺口使用 `BlockGap`、重叠冲突使用 `BlockConflict` 显式表示，不用零填充或静默选边冒充唯一数据。
- 重叠报文保留为带 packet/seq/offset/data 的 `Fragment`，并提供 `first_observed` 与 `last_observed` 候选流。
- `UncertainRanges` 标出无法唯一确定的字节，`IncompleteRanges` 标出缺口和预算停止时未完成的范围。
- `Messages(delim)` 只解析连续唯一确定的数据，遇到缺口或冲突即中断，不会跨越未知字节拼接应用消息。
- `StreamResult` 字段带 JSON 标签，可直接 marshal/unmarshal，重新读取后保留候选、片段来源和不确定范围。
- 反方向 ACK 只会作为缺口佐证（`ack_confirmation`），不会补造缺口内未采集字节。
- 同一四元组重开连接会生成独立 `Generation`，避免跨连接拼接相同端口的旧片段。
- `Interpret(rule)` 可选择 `first_observed` 或 `last_observed` 解释；上层消息保留采用片段来源，并继续列出未解决范围。
- `SaveSnapshot`/`LoadAssemblerSnapshot` 可保存重开后继续处理，原始片段、候选和缺口状态保持不变。
- `CompareStreamResults` 可在乱序补入、ACK 佐证或重开续处理后说明结论被加强、解决、失效或仍未解决。
- 解释分支：`Branch`/`NewBranch`/`Choose` 允许在同一重叠处选取不同原始片段后各自继续解析；分支间共享的已确认内容保持一致，一个分支的假设不会自动成为另一个分支的事实。
- `Branch.View` 按分支采用的片段解析上层消息，保留采用区间、仍冲突区间和缺口；消息精确追溯到所采用的 `Fragment`（报文/seq/offset）。
- `CompareMessages` 在后来补入字节或收到相反证据时指出哪些上层消息需要重新解释，并区分真实内容变化（`content_changed`，旧结论失效）、边界划分变化（`boundary_changed`）和置信依据变化（`confidence_changed`，内容仍可用）。
- `Branch.Reconcile` 在某读法获得两份以上独立佐证时由分析人员显式接受多数读法并记录理由；单个重传不会静默翻转分支，`Reconverged` 判断两条解释是否重新收敛为相同的上层消息集。
- `SaveCaseFile`/`LoadCaseFile` 把汇编快照与所有分支（含当时选择理由）一起持久化，重开后可继续任一分支。
- 包数、会话数、已接收流字节和乱序缓存字节预算。

运行测试：

```sh
go test ./...
```

重新生成自带抓包：

```sh
go run ./cmd/genpcap > testdata/known.pcap
```
