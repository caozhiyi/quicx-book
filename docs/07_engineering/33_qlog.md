# 33. 黑匣子：Qlog 可观测性实践

Metrics 能告诉你"丢包率突然升到 5%"，LogContext 能帮你定位到"是连接 abc123"。但接下来呢？那一秒钟里，包是怎么发的、ACK 是怎么回的、拥塞窗口是怎么变化的？丢包是因为链路拥塞还是因为乱序超时？cwnd 的跌落是 Cubic 的正常减半还是 BBR 的 PROBE_RTT 主动排空？这些问题靠聚合指标和文本日志都无法回答——你需要的是协议层的飞行记录仪。

---

## 33.1 文本日志的视野极限

文本日志是人类最熟悉的调试工具。`LOG_ERROR("packet loss detected, pn=42")` 这样一行日志，能告诉你"发生了丢包"。但一秒钟内有上千个包在收发、数十次 ACK 在反馈、拥塞窗口在持续调整——面对这个密度的协议交互，"grep 日志找问题"的方式彻底失效。

原因有三。

第一，文本日志是非结构化的。每个开发者写日志的格式不同，字段不同，甚至同一个事件在不同版本里的日志格式都可能变化。你无法对非结构化文本做精确的时序查询——"找出这条连接在第 3 秒到第 5 秒之间所有 cwnd 变化事件"这种问题，用 grep 几乎不可能高效回答。

第二，文本日志缺乏协议语义。`LOG_INFO("cwnd updated to 14000")` 看起来有信息量，但它没有告诉你：此刻的 RTT 是多少、bytes_in_flight 是多少、这次更新是因为收到 ACK 还是因为检测到丢包、拥塞控制当前处于什么状态。一个数字脱离了上下文就失去了诊断价值。

第三，文本日志无法可视化。拥塞控制的行为本质上是一条时间序列曲线——cwnd 和 bytes_in_flight 随时间的变化轨迹。用文本日志看这条曲线，就像用数字表格看股票走势——信息都在，但模式完全看不出来。

一个引入场景可以说明这种盲区。某条连接的首字节延迟突然从 50ms 跳到 2s。Metrics 看到了延迟飙升，LogContext 定位了连接 ID，但排查人员翻了几百行日志仍然无法确定原因——是握手卡在了 Retry？是 0-RTT 被拒导致重走 1-RTT？是慢启动阶段 cwnd 太小而初始数据量太大？是接收方的流控窗口过小触发了背压？这些可能性在文本日志里都表现为"请求变慢了"，无法区分。

需要的是另一种工具：结构化的、带完整协议语义的、可机器解析和可视化的事件序列。这就是 qlog。

---

## 33.2 qlog 标准：QUIC 世界的飞行记录仪

qlog 是 IETF 正在标准化的 QUIC/HTTP/3 事件日志格式（draft-ietf-quic-qlog 系列）。它的核心思想是：为协议栈的每一个关键动作定义一个标准化的 JSON 事件，带精确时间戳、完整字段、明确的事件名。所有实现——无论是 quicX、quiche、ngtcp2 还是 msquic——只要输出符合 qlog schema 的事件流，就能被同一套工具链消费和可视化。

qlog 将事件分为五个域：

**connectivity** 域记录连接的宏观生命周期：连接建立（`connection_started`，携带双端 IP、端口、连接 ID）、状态变迁（`connection_state_updated`，从 `initial` 到 `handshake` 到 `connected` 再到 `closing`/`draining`/`closed`）、连接关闭（`connection_closed`，携带错误码、原因、触发方式）。这些事件回答的是"连接活了多久、怎么建的、怎么断的"。

**transport** 域记录包级别的收发事实：`packet_sent` 和 `packet_received` 是最高频的两个事件，每个事件携带包号、包类型（initial/handshake/0RTT/1RTT）、包大小、帧类型列表。`packets_acked` 记录哪些包号被 ACK 确认了，`packet_lost` 记录哪些包号被判定为丢失以及判丢原因（时间阈值、包阈值、PTO 超时）。这些事件回答的是"线上到底跑了什么"。

**recovery** 域记录恢复和拥塞控制的内部状态：`metrics_updated` 定期快照 min_rtt、smoothed_rtt、latest_rtt、rtt_variance、cwnd、bytes_in_flight、ssthresh、pacing_rate 等核心参数；`congestion_state_updated` 记录状态机跳转（slow_start → congestion_avoidance → recovery → application_limited）。这些事件回答的是"发送引擎此刻在想什么"。

**security** 域记录密钥的安装与废弃。**http3** 域记录 HTTP/3 帧的创建与解析。这两类事件在诊断加密级别切换和应用层帧异常时有用，但频率远低于 transport 和 recovery。

qlog 的输出格式采用 JSON Text Sequences（RFC 7464）：每行一个独立的 JSON 对象，流式写入友好。这意味着即使进程崩溃，已经写到磁盘的事件也不会因为缺少闭合括号而丢失——对"黑匣子"来说，这个特性至关重要。

一个 qlog 文件的结构如下：

```
{"qlog_format":"JSON-SEQ","qlog_version":"0.4"}
{"title":"QuicX client","vantage_point":{"name":"client","type":"client"},"common_fields":{"protocol_type":"QUIC"},"configuration":{"time_offset":0,"time_units":"us"}}
{"time":0.000,"name":"quic:connection_started","data":{"src_ip":"10.0.0.1","src_port":12345,"dst_ip":"10.0.0.2","dst_port":443,"src_cid":"a1b2c3d4","dst_cid":"e5f6a7b8"}}
{"time":15.234,"name":"quic:packet_sent","data":{"packet_number":0,"packet_type":"initial","packet_size":1200,"frames":["crypto","padding"]}}
{"time":45.678,"name":"quic:packet_received","data":{"packet_number":0,"packet_type":"initial","packet_size":1200,"frames":["crypto","ack"]}}
{"time":45.700,"name":"quic:connection_state_updated","data":{"old_state":"initial","new_state":"handshake"}}
```

第一行是格式声明，第二行是 Trace 元数据（谁在记录、时间单位是什么），之后每行是一个事件。时间戳以微秒为单位记录，输出时转换为毫秒并保留三位小数。quicX 遵循 qlog v0.4 schema，事件类型定义在 `connectivity_events.h`、`transport_events.h`、`recovery_events.h` 中，共 19 种事件。

---

## 33.3 生产环境的三道保险：编译开关、连接采样与事件过滤

qlog 的信息量巨大——全开意味着每收发一个包都要构造一个 JSON 事件对象、序列化、入队、写磁盘。一条活跃连接每秒可能产生上千个 transport 事件。如果同时有一万条连接，qlog 本身就会成为性能瓶颈。quicX 用三层控制来解决这个问题：

**第一层：编译期开关**。CMake 选项 `QUICX_ENABLE_QLOG` 控制 qlog 的编译。当设为 OFF 时，所有 qlog 宏（`QLOG_PACKET_SENT`、`QLOG_METRICS_UPDATED`、`QLOG_CONNECTION_STARTED` 等）展开为 `((void)0)`——编译器直接优化掉，不会生成任何机器码。这是最彻底的"关闭"，适用于对延迟极度敏感、完全不需要协议诊断的场景。

**第二层：连接级采样**。即使编译开启了 qlog，也不意味着每条连接都要记录。`QlogManager::ShouldSampleConnection()` 根据配置的采样率决定是否为新连接创建 Trace。采样方式是确定性的：对连接 ID 做哈希，取模后与采样率比较。同一个连接 ID 的采样结果永远相同——这对复现问题很重要。采样率设为 0.01 意味着只有 1% 的连接会被记录，开销降低两个数量级。被跳过的连接不会创建 `QlogTrace` 对象，后续所有事件发射点的 trace 指针为空，宏直接短路返回。

**第三层：事件级过滤**。即使某条连接被采样选中，也不一定要记录所有 19 种事件。`QlogConfig` 提供白名单和黑名单两种机制：白名单非空时只记录白名单中的事件，黑名单非空时排除黑名单中的事件。过滤发生在 `QlogTrace::ShouldLogEvent()` 中，在序列化之前——被过滤的事件不会消耗序列化和写入的开销。

一个典型的生产配置：编译期开启 qlog，采样率 0.01（1% 连接），白名单只保留 connectivity 和 recovery 域的事件（忽略 transport 域的海量包收发事件）。这种配置下，qlog 的 CPU 开销对整体吞吐几乎没有可测量的影响，磁盘写入量也在可控范围内。

三层控制的设计逻辑是递进的：编译期保证零开销的可能性 → 运行时控制记录的连接范围 → 事件级控制记录的信息精度。每一层都是可选的，可以根据生产环境的资源约束灵活组合。

---

## 33.4 异步写入：不让 I/O 阻塞协议路径

事件采集发生在收发包的热路径上——每收到一个包、每检测到一次丢包、每更新一次拥塞窗口，都可能触发 qlog 事件。如果写磁盘是同步的，一次磁盘抖动就能让协议处理卡住数毫秒，这对延迟敏感的 QUIC 连接是不可接受的。

quicX 的 `AsyncWriter` 把事件写入从协议线程剥离出来。整个写入管线分为三个阶段：

**阶段一：序列化**（在协议线程上，无锁）。`QlogTrace::LogEvent()` 在连接所属的事件循环线程上执行。它先通过 `ShouldLogEvent()` 检查事件是否被过滤，然后调用 `JsonSeqSerializer::SerializeEvent()` 将事件对象转换为一行 JSON 字符串。这个过程不涉及 I/O，不需要锁——`QlogTrace` 是每连接独占的，遵循 One-Loop-Per-Thread 的线程归属约定。Debug 模式下通过 `owner_thread_id_` 断言验证这一点。

**阶段二：入队**（跨线程，一次锁操作）。序列化后的字符串被包装成 `WriteTask`（包含连接 ID 和数据），通过 `ThreadSafeQueue::Push()` 放入异步队列。这是整条管线上唯一的跨线程同步点——一次 mutex lock/unlock，耗时在纳秒级。队列容量由 `QlogConfig::async_queue_size`（默认 10000）控制。

**阶段三：批量写入**（在独立的写入线程上）。`AsyncWriter` 启动一个专用线程运行 `WriterLoop()`。循环逻辑是：每次从队列中批量取出最多 1000 条任务，按连接 ID 分组写入对应的文件。刷盘策略是"批量满或时间到"——达到 1000 条或距上次刷盘超过 100ms（`flush_interval_ms`）就触发一次 flush。无任务时休眠 10ms，避免空转消耗 CPU。

每条连接的 qlog 输出到独立文件，文件名格式为 `{timestamp}_{cid_prefix}.qlog`。连接级文件隔离意味着：不同连接的写入不会互相竞争文件锁，一条连接的 trace 文件可以独立打开、独立分析。

连接关闭时，`QlogManager::RemoveTrace()` 调用 `QlogTrace::Flush()` 确保最后的事件被写入，然后关闭文件。这保证了即使连接异常终止，已记录的事件也不会丢失——qlog 文件的完整性不依赖连接的正常关闭。

从协议线程的视角看，qlog 的开销只有两步：一次 JSON 序列化（字符串拼接，无堆分配的热路径上通常在微秒级）和一次队列 push（纳秒级）。磁盘 I/O 完全不可见。

---

## 33.5 拥塞控制的透视镜：qlog 与 BBR/Cubic 的集成

qlog 最大的价值不在于"记录了什么"，而在于"能看到什么"。在所有协议子系统中，拥塞控制是最需要 qlog 的——它的行为高度动态、状态机跳转频繁、决策逻辑与多个输入信号交织，文本日志几乎无法有效表达。

quicX 的所有拥塞控制算法（Reno、Cubic、BBRv1/v2/v3）都通过 `ICongestionControl::SetQlogTrace()` 接口接入 qlog。Trace 指针沿连接 → SendManager → SendControl → CongestionControl 的路径传递。一旦接入，拥塞控制器在每次状态变化时自动发射 `congestion_state_updated` 事件，在每次 recovery 指标变化时发射 `metrics_updated` 事件。

以一次典型的丢包→快恢复→带宽探测过程为例，qlog 事件序列如下：

```
t=1000.000  recovery:metrics_updated         cwnd=65536, in_flight=60000, srtt=30ms
t=1000.100  quic:packet_received             pn=500, type=1RTT, frames=[ack]
t=1000.100  quic:packets_acked               ranges=[{480,500}], delay=5ms
t=1000.100  recovery:metrics_updated         cwnd=68000, in_flight=55000, srtt=29ms
t=1000.200  quic:packet_received             pn=501, type=1RTT, frames=[ack]
t=1000.200  recovery:packet_lost             pn=450, trigger=time_threshold
t=1000.200  recovery:congestion_state_updated old=congestion_avoidance, new=recovery
t=1000.200  recovery:metrics_updated         cwnd=34000, in_flight=40000, ssthresh=34000
t=1000.500  quic:packets_acked               ranges=[{501,520}]
t=1000.500  recovery:congestion_state_updated old=recovery, new=congestion_avoidance
t=1000.500  recovery:metrics_updated         cwnd=34500, in_flight=30000
```

从这段事件序列中可以直接读出完整的诊断信息：t=1000.200 时，包号 450 因为超过时间阈值被判定丢失；拥塞控制从 congestion_avoidance 进入 recovery；cwnd 从 68000 减半到 34000；300ms 后恢复完成，cwnd 开始线性增长。如果换成文本日志，这段信息散落在十几行格式不一的 `LOG_DEBUG` 中，时间对齐和因果关系全靠人肉推断。

在 qvis（qlog 的标准可视化工具）中，上述事件序列会被渲染为两条时间序列曲线：cwnd（蓝色）和 bytes_in_flight（橙色）。丢包事件用红色竖线标注，状态跳转用背景色区分。拥塞控制的行为模式——慢启动的指数增长、拥塞避免的线性增长、丢包后的阶跃下降、恢复后的重新探索——在图上一目了然。

这种可视化能力是 qlog 区别于所有其他日志方案的核心价值。Metrics 告诉你"平均 cwnd 是多少"，qlog 告诉你"cwnd 在那一刻为什么变成了这个值"。

---

## 33.6 现场还原：从 qlog 事件到问题诊断

qlog 是为诊断而生的。它的价值在最后一步兑现：当线上出了问题，你拿到一个 `.qlog` 文件，能多快地还原现场、定位根因。

**工具链**。qvis（https://qvis.quictools.info/）是 qlog 的标准可视化工具，由 Hasselt 大学维护。它可以直接在浏览器中打开 qlog 文件，提供连接时间线视图（每个包的发送/接收/确认/丢失）、拥塞控制视图（cwnd/RTT/in_flight 随时间的曲线）、流状态视图（每条流的数据传输进度）。不需要安装，不需要配置——把文件拖进去就能看。

**三个典型诊断场景**：

*场景一：握手超时*。连接首字节延迟从 50ms 飙到 2s。打开 qlog，找到 `connection_started` 事件的时间戳，往后看：`packet_sent`（Initial 包）正常发出，但 `packet_received` 迟迟没有出现——说明服务端的 Initial 回包在路上丢了。继续看：PTO 触发，客户端重发了 Initial 包，第二次收到了回包。整个过程在 connectivity 事件序列中清晰展开：一次 Initial 丢包 + 一次 PTO 重传 = 额外 1 个 RTT 延迟。

*场景二：吞吐骤降*。某条连接的下载速度从 50 Mbps 突然跌到 5 Mbps。打开 qlog 的 recovery 视图：cwnd 在 t=10s 处从 200KB 骤降到 10KB，`congestion_state_updated` 显示从 `congestion_avoidance` 跳到 `recovery`，同时 `packet_lost` 显示大量连续包号被判丢。原因是一次突发丢包事件触发了拥塞窗口的大幅缩减。进一步看 `metrics_updated`：丢包后 srtt 并未显著增加，说明链路延迟没有变化，丢包更可能是随机丢包（如无线环境）而非拥塞。如果使用 BBR 而非 Cubic，这种场景的影响会更小——这就是算法选择的决策依据。

*场景三：连接迁移失败*。客户端从 WiFi 切换到 4G 后连接断开。打开 qlog 的 connectivity 视图：`connection_state_updated` 显示状态从 `connected` 直接跳到 `closing`，没有经过迁移流程。回溯 transport 事件：没有看到 `PATH_CHALLENGE` 的发送——说明客户端没有触发迁移，可能是因为可用的 Connection ID 已经耗尽（`connection_id_updated` 事件序列中没有新 CID 的发放），或者 NAT rebinding 后的新路径未被检测到。

**与 Wireshark 抓包的互补关系**。qlog 看的是"实现的内部状态"——拥塞窗口、RTT 估计、丢包判定逻辑、状态机跳转；Wireshark 看的是"线上的真实字节"——包的到达时间、加密后的载荷、ACK 的实际范围。两者结合形成完整的诊断视野：如果 qlog 显示 cwnd 在某个时刻骤降但 Wireshark 没有看到对应的丢包，说明丢包判定算法可能过于激进（假阳性）。如果 Wireshark 显示有包到达但 qlog 没有 `packet_received` 事件，说明解密失败或包被丢弃在解码层——这是 `packet_dropped` 事件应该覆盖但尚未实现的领域。

qlog 的设计哲学与 Metrics 和 LogContext 形成互补：Metrics 用聚合统计发现异常趋势，LogContext 用身份标签定位到具体连接，qlog 用结构化事件序列还原协议现场。三者各有分工，逐级递进——从"系统哪里有问题"到"是谁的问题"再到"那一刻到底发生了什么"。
