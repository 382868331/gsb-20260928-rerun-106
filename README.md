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
- `BranchSet` 支持解释分支：`Fork` 在重叠冲突处选择不同证据继续解析，共享的已确认内容在所有分支间保持一致，某分支的假设不会泄漏到兄弟分支。
- `BranchChoice` 记录每次选择的 packet 与理由；`SaveBranchSet`/`LoadBranchSet` 保存重开后任一分支可继续，理由不丢失。
- `CompareInterpretations` 并排比较两个分支，区分真实内容变化（`content_change`）、边界划分变化（`boundary_change`）和置信依据变化（`confidence_change`）。
- `BranchSet.Reassess` 在补入与某分支一致的原始报文后，在消息层区分 `content_change`（字节变化或变得不可唯一确定，必须重新解释）、`boundary_change`（字节一致但消息切分移动，必须重新解释）和 `confidence_change`（内容与边界不变但证据集合变化，结论可引用但需补注）；未受影响的消息标为 `unchanged` 可直接引用。
- 每条重评结论都带 `usability`（`citable`/`needs_addendum`/`must_reinterpret`），并分别列出实际采用的原始片段（`adopted_fragments`）、新增加持片段（`added_support_fragments`）和新增矛盾片段（`contradicting_fragments`）；证据只增加数量不会自动变成另一分支的事实，矛盾片段只列示、不被采纳。
- 重评结果（含采用/新增/矛盾片段与前后片段快照）保存在 `BranchSet.Reassessments` 中，随 `SaveBranchSet`/`LoadBranchSet` 在重开后完整保留依据。
- 包数、会话数、已接收流字节和乱序缓存字节预算。

运行测试：

```sh
go test ./...
```

重新生成自带抓包：

```sh
go run ./cmd/genpcap > testdata/known.pcap
```
