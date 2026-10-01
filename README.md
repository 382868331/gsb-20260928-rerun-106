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
- 包数、会话数、已接收流字节和乱序缓存字节预算。

运行测试：

```sh
go test ./...
```

重新生成自带抓包：

```sh
go run ./cmd/genpcap > testdata/known.pcap
```
