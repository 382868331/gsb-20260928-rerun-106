# tcprecon — 离线 TCP 双向会话还原取证核心

本项目只读取**离线人工抓包文件**（经典 libpcap 格式），不监听任何真实网卡。
后续协议解析可以直接建立在 session 包输出的会话、原始证据与重组结果之上。

## 能力

- **会话身份**：以 4 元组 + 握手 ISN 标识连接；同一 4 元组复用地址时按 Incarnation 区分新连接。
- **原始证据**：归属到会话的每个 TCP 段都保留帧号、方向、序号、标志位与处置结论（syn/assembled/buffered/retransmit/conflict/late-after-close/dropped/control）。
- **双向重组**：按相对序号（SYN 占 0，首字节为 1）同时还原 c2s / s2c。
- **乱序**：先到的远端片段进入待重组缓冲，空洞补齐后连续交付；支持 32 位序号回绕。
- **重传与重叠冲突**：字节完全一致记为 retransmit；重叠内容不一致记为 OVERWRITE-CONFLICT，记录冲突位置、原字节与新字节，并保留**先到**字节。
- **数据缺口**：缺失区间以显式 GAP 范围输出，**绝不补零**冒充完整数据。
- **关闭与迟到隔离**：FIN/ACK 四次挥手或 RST 关闭会话；关闭后到达的片段记为 late-after-close 证据，不会串入复用相同地址的新会话。
- **资源预算**：可限制会话数、处理帧数、单方向重组字节数与全局字节数；超预算的片段被扣留并记录 DROP，已还原内容保持不越界。

## 目录

- pcapio/ — pcap 读写、以太网/IPv4/IPv6/TCP 解析、确定性帧构造器。
- session/ — 会话身份、证据账本、双向重组、关闭与预算。
- cmd/genpcap/ — 依据已知通信过程生成自带抓包 testdata/capture.pcap。
- cmd/tcprecon/ — 命令行还原工具。
- testdata/capture.pcap — 随仓库提供的人工抓包（也可用生成器复现）。

## 使用

还原自带抓包：go run ./cmd/tcprecon -f testdata/capture.pcap

重新生成人工抓包（已知通信过程的独立实现）：go run ./cmd/genpcap -out testdata/capture.pcap

演示资源预算耗尽：go run ./cmd/tcprecon -f testdata/capture.pcap -max-bytes-per-dir 13

输出中 [DATA rel=a..b] 为真实字节，[GAP rel=a..b N bytes missing] 为明确标注的缺失区间；证据区列出重传/覆盖冲突与关闭后迟到片段。

## 自带抓包场景

testdata/capture.pcap 包含两次复用同一 4 元组的连接：

1. 会话 A：请求 + 乱序响应（第二段先到）、相同重传、关闭后的迟到数据。
2. 会话 B：中间 4 字节永久缺失形成显式缺口、覆盖冲突（保留先到字节）、RST 关闭及关闭后迟到数据。

## 测试

go test ./... 使用独立于重组器的 oracle 字符串对照还原内容，并覆盖乱序补齐、序号回绕、重传/冲突、迟到隔离、缺口不补零和预算耗尽结果。
