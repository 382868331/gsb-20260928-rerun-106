# Go 网络流量取证核心

当前版本只读取人工 pcap，不监听真实网卡。核心提供：

- 以太网/IPv4/TCP 解析。
- 四元组和连接代次组成的会话身份。
- 原始报文、乱序、重传、重叠冲突、迟到片段和缺口证据。
- c2s/s2c 双向重组；缺口使用 `BlockGap`，冲突字节使用 `BlockAmbiguous`，并通过 `UncertainRanges` 标明无法唯一确定的范围。
- 重叠且内容不同的报文全部保留为片段，可按 `CandidateFirstObserved` 和 `CandidateLastObserved` 规则读取候选流；规范 `Bytes` 不删除另一方证据。
- `ParseApplicationMessages` 只在连续、唯一确定的数据块中解析消息，遇到缺口或冲突字节会输出阻塞范围，不把缺口跨成合法内容。
- `Export` / `ImportAssembler` 使用 JSON 快照保存已确定片段、候选、缺口、证据、预算状态和未完成范围，重新读回保留同等不确定性。
- 包数、会话数、已接收流字节和乱序缓存字节预算。

运行测试：

```sh
go test ./...
```

重新生成自带抓包：

```sh
go run ./cmd/genpcap > testdata/known.pcap
```
