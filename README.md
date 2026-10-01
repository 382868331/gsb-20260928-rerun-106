# Go 网络流量取证核心

当前版本只读取人工 pcap，不监听真实网卡。核心提供：

- 以太网/IPv4/TCP 解析。
- 四元组和连接代次组成的会话身份。
- 原始报文、乱序、重传、重叠冲突、迟到片段和缺口证据。
- c2s/s2c 双向重组，缺口使用 `BlockGap`、重叠冲突使用 `BlockConflict` 显式表示，不用零填充或静默选边冒充唯一数据。
- 重叠报文保留为带 packet/seq/offset/data 的 `Fragment`，并提供 `first_observed` 与 `last_observed` 候选流。
- `UncertainRanges` 标出无法唯一确定的字节，`IncompleteRanges` 标出缺口和预算停止时未完成的范围。
- `Messages(delim)` 只解析连续唯一确定的数据，遇到缺口或冲突即中断，不会跨越未知字节拼接应用消息。
- 反向报文的 ACK 作为 `peer_confirm` 证据记录对端已确认接收的范围（`PeerAckedRanges`），其中从未采集到的部分标为 `PeerAckedMissing`；确认只作证据，不会凭空补出未采集的字节。
- `Resolve(rule, delim)` 在用户选定一种候选解释（`first_observed`/`last_observed`）后解析上层消息，每条消息标明采用的片段证据（`Sources`）、按规则裁定的范围（`AssumedRanges`）以及仍未解决的范围（`UnresolvedRanges`）。
- `Snapshot`/`RestoreSnapshot` 以 JSON 保存并恢复全部分析状态（含已关闭会话的代次），重开后可继续抓包分析，原始片段保持不变。
- `DiffStreamResults(before, after)` 对比两次结果，重新说明哪些结论被加强（缺口被乱序片段填上）、失效（唯一字节出现冲突观察）或新增。
- `StreamResult` 字段带 JSON 标签，可直接 marshal/unmarshal，重新读取后保留候选、片段来源和不确定范围。
- 包数、会话数、已接收流字节和乱序缓存字节预算。

运行测试：

```sh
go test ./...
```

重新生成自带抓包：

```sh
go run ./cmd/genpcap > testdata/known.pcap
```
