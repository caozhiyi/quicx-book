# 32. 透明的眼睛：Metrics、日志上下文与可观测性基座

协议库"能跑"和"能上线"之间有一条鸿沟。握手跑通了、流能打开了、帧能收发了——功能上已经完整。但如果你现在把这个库丢到生产环境里，第一个问题不会是"它能不能跑"，而是"它出了问题你看不看得见"。RTT 在缓慢上升，你知道吗？某条流被流控卡住了十秒，你发现了吗？某个连接的拥塞窗口在慢启动后再也没长回来，日志里有一个字提到过吗？**你无法优化你看不见的东西**。

---

## 32.1 协议问题为什么不能只靠业务日志发现

业务日志记录的是"发生了什么"——收到请求、返回响应、读写数据库。Metrics 记录的是"状态如何"——连接活跃数、RTT 分布、丢包率、拥塞窗口大小。这两类信息的粒度和关注点完全不同。

协议层的衰减有一个特征：**它是渐进的、沉默的**。RTT 从 30ms 慢慢飘到 300ms，不会触发任何业务异常——HTTP 请求仍然在返回 200，只是越来越慢。流控窗口见底后，发送方停下来等接收方的 MAX_DATA，这段等待在业务日志里完全不存在——你不会为每个 BLOCKED 帧打一条 `LOG_INFO`。拥塞窗口在一次丢包事件后降到极低值并迟迟恢复不上来，连接的吞吐跌到带宽的十分之一——但应用层只看到"请求变慢了"，无法定位到拥塞控制层。

一个真实场景可以说明这种盲区。线上某条连接的下载吞吐忽然从 100 Mbps 跌到接近零。业务日志显示请求正常返回、没有超时、没有错误码。排查人员花了两小时翻日志、抓包、对比客户端和服务端时间戳，最终发现原因是：接收方的流控窗口在一次短暂的处理延迟后被耗尽，发送方发出了 `DATA_BLOCKED` 帧，然后停下来等——一直等。如果当时有一个 `flow_control_blocked` 计数器在 dashboard 上实时展示，排查时间可以从两小时缩短到两分钟。

这就是 Metrics 存在的理由：它让协议层的内部状态从"隐式"变成"显式"，从"事后翻日志"变成"实时看面板"。

---

## 32.2 76 个指标的分层设计：从 UDP 到 HTTP/3

quicX 的 `MetricsStd` 预定义了 76 个指标，分布在 18 个类别中。数量不少，但重点不是把 76 个名字列出来——而是理解"为什么要分这些层"。

协议栈本身就是分层的，指标也应该跟着分。一个请求从应用层进入 HTTP/3，经过 QPACK 压缩、帧封装、QUIC 流管理、拥塞控制、加密、打包，最终通过 UDP 发出去。每一层都可能出问题，而每一层出问题时的表征是不同的。

从底向上看这些层次：

**UDP 层**（6 个指标）记录的是最原始的收发事实：收了多少包、发了多少包、丢了多少包、发送失败了多少次。这是整个协议栈的地基——如果 `udp_send_errors` 在涨，后面所有层的分析都可以先停下来。

**QUIC 连接层**（6 个指标）关心的是连接本身的生命周期：当前活跃连接数（Gauge）、握手成功/失败计数（Counter）、握手耗时分布（Histogram，桶边界从 1ms 到 1s）。握手耗时的 P99 如果突然飙升，可能意味着 TLS 层出了问题、网络路径变长了、或者 Retry 机制被频繁触发。

**QUIC 包层**（6 个指标）跟踪的是包级别的传输健康度：收包数、发包数、重传数、判丢数、确认数、丢弃数。重传率 = 重传数 / 发包数，这是最直接的链路质量指标。

**流层**（7 个指标）关心的是 Stream 维度：活跃流数量（Gauge）、创建/关闭计数、流级别的收发字节数、被 RESET 的流数量。如果 `streams_reset_tx` 在短时间内暴涨，通常意味着应用层在大量取消请求。

**流控层**（2 个指标）是最容易被忽略但最有诊断价值的：`flow_control_blocked`（连接级背压次数）和 `stream_data_blocked`（流级背压次数）。这两个计数器是零就健康，非零就值得警惕。

**拥塞控制层**（4 个指标）暴露的是发送引擎的核心状态：拥塞窗口大小（Gauge）、在途字节数（Gauge）、拥塞事件计数（Counter）、慢启动退出次数（Counter）。cwnd 和 bytes_in_flight 两条曲线放在一起看，能直接判断发送方是被拥塞卡住了还是被流控卡住了。

**性能/延迟层**（4 个指标）包括 Smoothed RTT、RTT 方差、最小 RTT（三个 Gauge）和包处理耗时直方图。RTT 的三个值分别代表"平均有多远""波动有多大""最好能多快"，三者结合能判断链路是稳定变慢了还是在间歇性抖动。

**HTTP/3 层**（8 + 4 个指标）是应用层最关心的：请求计数、活跃请求数、请求耗时直方图、状态码分布（2xx/3xx/4xx/5xx 分别计数）。状态码分布是后端健康度的直接指标——如果 5xx 占比突然上升，问题可能在协议层之上。

其余类别覆盖了 0-RTT（接受/拒绝计数）、Path MTU（当前 MTU 值）、连接迁移（成功/失败计数）、Retry 机制（触发原因分类）、ACK 统计（延迟分布、Range 数量分布）、PTO 统计（每连接 PTO 次数直方图）等。

这 76 个指标的**类型分布**也值得注意：大约 53 个是 Counter（只增不减的累计值，适合"总共发生了多少次"的问题）、15 个是 Gauge（可增可减的瞬时值，适合"现在是多少"的问题）、8 个是 Histogram（分布观测值，适合"通常是多少、极端情况有多慢"的问题）。三种类型对应三种不同的监控问题——Counter 看趋势，Gauge 看当前，Histogram 看分布。

---

## 32.3 热路径上的零锁采集：Thread-Local 存储与全局聚合

76 个指标定义好了，但采集发生在哪里？答案是：发包路径、收包路径、ACK 处理路径、拥塞窗口调整路径——全是热路径。每收一个 UDP 报文就要给 `udp_packets_rx` 加一，每发一个 QUIC 包就要给 `quic_packets_tx` 加一，每调整一次 cwnd 就要更新 `congestion_window_bytes`。如果这些操作需要加锁，Metrics 系统本身就会成为性能瓶颈。

quicX 的解法是一个三层架构：静态门面 → 全局注册中心 → 线程本地存储。

最上层是 `Metrics` 类——一个纯静态的门面。所有采集调用都通过它：`Metrics::CounterInc(id, val)`、`Metrics::GaugeSet(id, val)`、`Metrics::HistogramObserve(id, val)`。这些方法没有虚函数、没有锁、没有间接跳转。

最底层是 `ThreadMetricStorage`——每个线程通过 `thread_local` 持有一个独立的存储实例。Counter 是 `atomic<uint64_t>` 数组，Gauge 是 `atomic<int64_t>` 数组，Histogram 是 HistogramStorage 数组（包含桶计数、总和、次数）。写操作使用 `memory_order_relaxed`——最弱的内存序，不需要任何同步屏障。这是合理的：指标采集不需要精确的跨线程一致性，Prometheus 抓取时能拿到近似最新值就够了。

中间是 `GlobalRegistry`——一个 Meyers Singleton。它持有所有指标的元数据（名字、帮助文本、类型、标签、直方图桶边界）和一个活跃线程列表。当一个线程第一次调用 `Metrics::CounterInc` 时，`GetThreadStorage()` 会创建 `thread_local ThreadMetricStorage`，它的构造函数自动向 GlobalRegistry 注册自己。当线程销毁时，ThreadMetricStorage 的析构函数会把累积的数据合并到 GlobalRegistry 的"死线程累积器"（`dead_counters_`、`dead_gauges_`、`dead_histograms_`），然后从活跃列表中注销——数据不会因为线程退出而丢失。

以 `CounterInc` 的完整调用路径为例：

```
Metrics::CounterInc(MetricsStd::QuicPacketsTx, 1)
  → g_metrics_enabled == false ?  return;          // 全局开关短路
  → id == kInvalidMetricID ?      return;          // 哨兵值短路
  → GetThreadStorage()                             // thread_local 访问
    → storage.GetCounter(id)                       // 按需扩展数组
      → atomic.fetch_add(1, memory_order_relaxed)  // 无锁原子加
```

整个路径上没有互斥锁、没有条件变量、没有 CAS 重试循环。开销只有一次 thread_local 查找和一次 relaxed 原子加——在现代 CPU 上大约是 1-2 纳秒。如果全局开关关闭（`g_metrics_enabled == false`），开销更低：一次分支判断就返回了。

这个设计能成立，有一个前提条件：quicX 采用 One-Loop-Per-Thread 架构（第 4 章），每个连接绑定到一个固定的事件循环线程，连接的所有操作都在同一个线程上执行。这意味着一个连接的指标写入只会发生在一个线程的 ThreadMetricStorage 上——连 `memory_order_relaxed` 的原子操作实际上都是单线程串行的。thread_local 之所以安全，正是因为架构保证了"一个连接不跨线程"。

---

## 32.4 从 Export 到 Prometheus：指标的暴露路径

指标采集完了，存在各个线程的本地存储里。下一步是把它们聚合起来、格式化、暴露给外部监控系统。

聚合发生在 `GlobalRegistry::Collect()` 中。这是整个 Metrics 系统里唯一需要加锁的地方——Prometheus 每次抓取（通常每 15 秒或 30 秒一次）触发一次 Collect。Collect 的逻辑是：先拷贝死线程累积器作为基底，然后遍历所有活跃线程的 ThreadMetricStorage，把每个指标的值累加上去。遍历期间持有全局锁，但遍历的是指针数组（活跃线程列表），每个线程只做一次 `atomic.load(relaxed)` 读取——整个操作在线程数为几十的规模下耗时微乎其微。

格式化由 `Metrics::ExportPrometheus()` 完成。它生成 Prometheus 文本格式（version 0.0.4），三种类型各有固定模板：

Counter 最简单——`# HELP` + `# TYPE` + 一行值：

```
# HELP quicx_quic_packets_tx Total QUIC packets sent
# TYPE quicx_quic_packets_tx counter
quicx_quic_packets_tx 12345
```

Gauge 格式相同，只是 TYPE 行标记为 `gauge`。

Histogram 最复杂——需要生成累积桶（每个桶是"小于等于该边界的事件总数"）、总和、计数：

```
# HELP quicx_quic_handshake_duration_us QUIC handshake duration
# TYPE quicx_quic_handshake_duration_us histogram
quicx_quic_handshake_duration_us_bucket{le="1000"} 5
quicx_quic_handshake_duration_us_bucket{le="5000"} 12
quicx_quic_handshake_duration_us_bucket{le="10000"} 14
quicx_quic_handshake_duration_us_bucket{le="+Inf"} 15
quicx_quic_handshake_duration_us_sum 45000
quicx_quic_handshake_duration_us_count 15
```

暴露路径由 HTTP/3 层的 `MetricsHandler` 完成。在服务端启动时，如果 `MetricsConfig::http_enable` 为 true，`Server` 自动注册一个 GET 路由：

```
AddHandler(HttpMethod::kGet, "/metrics", MetricsHandler::Handle)
```

MetricsHandler 的实现极简：调用 `Metrics::ExportPrometheus()` 拿到格式化字符串，设置 `Content-Type: text/plain; version=0.0.4; charset=utf-8`，返回 200。Prometheus 直接抓取这个端点即可。

这形成了一个自举效应：quicX 的 HTTP/3 服务器能力被用来暴露 quicX 自己的运行指标。Metrics 系统不依赖外部 HTTP 框架，也不依赖额外的端口——它复用 quicX 自己的 HTTP/3 协议栈。

一个典型的生产部署链路是：quicX Server → `/metrics` 端点 → Prometheus 定期抓取 → Grafana 可视化。上线第一天最应该关注的几个面板：

| 面板 | 关键指标 | 告警阈值建议 |
|------|---------|-------------|
| 连接健康 | `connections_active`、握手耗时 P99 | 活跃数突降、P99 > 500ms |
| 传输质量 | 丢包率、重传率、RTT 三值 | 丢包率 > 2%、RTT P99 > 200ms |
| 流控状态 | `flow_control_blocked`、`stream_data_blocked` | 任何非零值 |
| 拥塞状态 | cwnd、bytes_in_flight | cwnd 持续低于 BDP 估计值 |
| HTTP/3 | 请求耗时 P99、状态码分布 | 5xx 占比 > 1%、P99 > 1s |

---

## 32.5 日志的迷雾：多连接并发时的身份困境

Metrics 能告诉你"系统整体状态如何"。但当你需要排查"某一条连接为什么异常"时，视角要从聚合值切换到单条日志——你需要看到那条连接在那个时刻到底发生了什么。

这时候一个新问题出现了：日志知道发生了什么事，但不知道是谁干的。

在 One-Loop-Per-Thread 模型下，一个事件循环线程同时服务数十甚至数百条连接。当这个线程的日志输出显示 `[ERROR] stream reset by peer` 时——它属于哪个连接？哪条流？如果日志里没有身份信息，排查就变成了在成千上万行日志中用时间戳和上下文推断"这行日志大概属于谁"——这基本上是一种猜谜游戏。

一个显而易见的解法是：让每个日志调用点手动传递连接 ID。Go 语言的 `context.Context` 就是这种风格——每个函数签名里都带着 context 参数，日志时从 context 里取出 trace ID。但这种方式放到 quicX 里意味着：上百个打日志的地方（`LOG_DEBUG`、`LOG_INFO`、`LOG_ERROR`）都要修改调用签名，传入连接 ID 或流 ID。侵入性极强，而且每增加一个新的打日志点就要记得带上 context——遗漏一个就是一行"失明"的日志。

有没有零侵入的方案？让现有的所有 `LOG_*` 调用完全不修改，但输出的每一行日志都自动携带"我属于哪个连接、哪条流"的信息？

---

## 32.6 栈式 RAII 守卫：50 行代码的精巧设计

quicX 的解法只有两个类、不到 50 行有效代码：`LogContext`（静态类，持有 thread_local 字符串缓冲区）和 `LogTagGuard`（RAII 守卫）。

`LogContext` 的核心是一个 `thread_local std::string`，预分配 256 字节。它提供三个操作：`Append(tag, len)` 追加标签、`Truncate(len)` 截断到指定长度、`GetTag()` 返回当前内容的 C 字符串。没有锁，没有动态分配——thread_local 保证每线程独占，预分配保证运行时不触发 `malloc`。

`LogTagGuard` 是一个 RAII 守卫。构造时记住缓冲区的当前长度（`old_len_`），然后追加标签；析构时把缓冲区截断回 `old_len_`。这形成了一个天然的**栈式 push/pop** 结构：

```
进入连接处理:  buffer = "conn:a1b2c3"          old_len = 0
  进入流处理:  buffer = "conn:a1b2c3|strm:4"   old_len = 11
  离开流处理:  buffer = "conn:a1b2c3"           Truncate(11)
离开连接处理:  buffer = ""                       Truncate(0)
```

在 quicX 的实际代码中，Guard 被放在关键入口点：

- **Worker 层**：收到一个连接的数据包时，构造 `LogTagGuard("conn:" + cid_hash)`。这个 Guard 的生命周期覆盖整个包处理过程——从帧解码、ACK 处理、流管理到响应发送
- **流处理层**：进入具体流的处理时，构造 `LogTagGuard("|strm:" + stream_id)`。注意前缀是 `|`——它追加在连接标签之后，用管道符分隔

日志的注入发生在 `BaseLogger::FormatLog()` 中。这个函数在格式化每一行日志时，会调用 `LogContext::GetTag()` 读取当前线程的上下文缓冲区内容。如果非空，插入日志前缀的方括号内。一行日志的完整面目是：

```
[INF|2026-03-19 10:30:00.123|conn:a1b2c3|strm:4|stream_manager.cpp:260] data received, 1024 bytes
```

五个字段依次是：日志级别、时间戳、连接标签、流标签、源码位置。前两个和最后一个是传统日志系统的标配，中间两个就是 LogContext 自动注入的——调用 `LOG_INFO("data received, %d bytes", len)` 的那行代码完全不知道自己的输出里会带上连接和流的身份信息。

这个设计有三个值得注意的细节。第一，`LogTagGuard` 提供了 `const char*` 的构造函数重载，避免在每次 Guard 构造时创建 `std::string` 临时对象——在热路径上每次省下一次堆分配。第二，缓冲区的 256 字节预分配覆盖了绝大多数场景：`"conn:a1b2c3|strm:4"` 不到 20 字节，即使有多层嵌套也远远够用。第三，整个机制的正确性同样依赖 One-Loop-Per-Thread——`thread_local` 之所以不需要锁保护，是因为一个线程在处理连接 A 的包时不会被中断去处理连接 B 的包。Guard 的构造和析构严格嵌套，不存在并发交错的可能。

与 Go 的 `context.Context` 相比，这个设计的取舍很明确：Go 选择显式传递（类型安全、可组合、但侵入性强），quicX 选择隐式注入（零侵入、对现有代码透明、但依赖线程模型假设）。在 One-Loop-Per-Thread 架构下，后者的假设总是成立的。

---

## 32.7 可观测性的三个层次：Metrics、LogContext 与 Qlog 的分工

Metrics 和 LogContext 是本章的两个主角。但 quicX 的可观测性实际上有三个层次，第三个是 Qlog——一种专门为 QUIC 设计的结构化事件日志格式（下一章展开）。这三者各有分工，不可互相替代。

| 工具 | 回答的问题 | 粒度 | 开销 | 生产环境策略 |
|------|-----------|------|------|-------------|
| Metrics | 系统整体健康吗？哪里在劣化？ | 聚合统计值 | 极低（thread-local 无锁） | 常开 |
| LogContext | 这行日志属于哪个连接、哪条流？ | 每行日志 | 极低（字符串追加） | 常开 |
| Qlog | 那一刻协议层到底发生了什么？ | 每个包/帧/事件 | 较高（结构化 JSON 写入） | 采样或按需开启 |

三者形成一个从宏观到微观的排查链路：**Metrics 发现异常**（dashboard 上 RTT P99 飙升）→ **LogContext 定位到连接**（找到那个时间段内 RTT 异常的连接 ID）→ **Qlog 还原现场**（回放那条连接的完整握手、ACK、丢包、重传序列，找到根因）。

从工程开销看，Metrics 和 LogContext 都可以在生产环境中常开——前者是 thread_local 原子操作，后者是字符串追加，两者的热路径开销都在纳秒级。Qlog 的开销更高（每个协议事件都要序列化为 JSON），因此通常采用采样策略：只对一定比例的连接开启 Qlog 记录，或者在 Metrics 触发告警后动态开启。

从设计哲学看，三者体现了可观测性的三种不同思路。Metrics 是**统计学思路**——用聚合值描述群体行为，擅长发现趋势和异常。LogContext 是**身份追踪思路**——不增加新信息，只给已有日志附加身份标签，让排查有迹可循。Qlog 是**录像回放思路**——把协议层的每个动作都记录下来，事后可以完整回放。

quicX 从架构上把三者分开实现、独立控制，但让它们共享同一个基础设施——thread_local 存储、One-Loop-Per-Thread 线程模型、Meyers Singleton 全局注册。三种工具的热路径开销都建立在同一个架构假设上：每个连接绑定到固定线程，不存在并发交错。正是这个假设，让 Metrics 可以用 relaxed 原子操作、LogContext 可以用裸 thread_local 字符串、Qlog 可以用无锁环形缓冲区——它们的低开销不是各自的巧妙，而是底层线程模型给出的统一红利。
