# 31. 一条 HTTP/3 连接的一生

帧体系、请求映射、头压缩引擎——所有零件已经摊在桌上了。但零件不是系统。读者还没有看到它们如何在一条真实的连接里协调运转：三条基础设施流是何时创建的？SETTINGS 交换完成后 QPACK 动态表怎么被激活？第一个请求从编码到路由走了哪些组件？多条请求并发时流控和压缩阻塞如何交织？关闭信号是怎样从 GOAWAY 传导到最后一条流的 FIN？这一章的任务就是把零件装回去：用一条 HTTP/3 连接从诞生到消亡的完整时间线，展示每个阶段哪些组件被激活、它们之间如何配合、异常时又如何收场。

---

## 31.1 QUIC 握手完成：HTTP/3 的起点

HTTP/3 连接不是凭空出现的。它有一个精确的起点：**QUIC 握手完成**。具体来说，当 TLS 1.3 握手结束、1-RTT 密钥可用、Transport Parameters 已交换后，QUIC 层通过一个回调通知上层——"传输通道已就绪"。HTTP/3 的全部初始化工作，都发生在这个回调里。

初始化的第一步是创建三条**基础设施流**。RFC 9114 §6.2 要求，每个端点必须发起一条 Control Stream（流类型 `0x00`）、一条 QPACK Encoder Stream（流类型 `0x02`）和一条 QPACK Decoder Stream（流类型 `0x03`）。这三条都是单向流，它们不承载任何 HTTP 请求或响应数据，而是承载连接级的控制指令和头压缩指令。

为什么必须是三条？因为 HTTP/3 把控制面和压缩面从数据面中彻底分离了。Control Stream 负责 SETTINGS 协商和 GOAWAY 关闭；QPACK Encoder Stream 负责向对端投递动态表的插入指令；QPACK Decoder Stream 负责向编码端反馈确认（Section Acknowledgment、Insert Count Increment）。这三条流是连接的"基础设施"——在第一个请求发出之前就必须就位。RFC 9114 §6.2 要求传输参数必须允许对端创建至少三条单向流，每条流的初始流控额度不低于 1024 字节。

quicX 的客户端在 `ClientConnection` 的构造函数中完成这一初始化：

```
handshake_done_cb_ → Client::OnConnection()
  → new ClientConnection(host, settings, quic_conn, ...)
    构造函数内部：
    1. MakeStream(kSend) → Control Stream
       └─ ControlClientSenderStream::SendSettings(settings)
    2. MakeStream(kSend) → QPACK Encoder Sender Stream
    3. MakeStream(kSend) → QPACK Decoder Sender Stream
    4. 绑定 QpackEncoder 的指令发送回调和解码反馈回调
  → Init()  // 启动 100ms 周期定时器，清理已完成的流
```

服务端的 `ServerConnection` 遵循相同的模式，但有一个微妙的差异：如果 QPACK 动态表容量和阻塞上限都为零（即不使用动态表），QPACK 流的创建会被跳过。这是一个"按需激活"的设计——对于不需要动态表压缩的轻量场景，减少不必要的流创建开销。

创建三条基础设施流的过程是异步的——`MakeStream` 返回的时机取决于 QUIC 层的流控额度。如果流创建失败（例如对端的 `max_uni_streams` 设置过小），连接将以 `H3_STREAM_CREATION_ERROR`（0x0103）终止。这条规则的背后逻辑是：没有 Control Stream 就无法协商参数，没有 QPACK 流就无法压缩头部——缺少任何一条基础设施流，HTTP/3 连接就不具备最基本的运行条件。

---

## 31.2 SETTINGS 交换：双方能力的对齐

三条基础设施流就位后，HTTP/3 连接进入第二个阶段：SETTINGS 交换。Control Stream 创建后立即发出的第一帧就是 SETTINGS——RFC 9114 §6.2.1 规定，**SETTINGS 必须是 Control Stream 上的第一帧**。如果接收方在 Control Stream 上先看到了任何其他帧，必须以 `H3_MISSING_SETTINGS`（0x010a）终止连接。

SETTINGS 帧携带三个关键参数：

| 参数 ID | 名称 | 含义 |
|---------|------|------|
| `0x01` | `QPACK_MAX_TABLE_CAPACITY` | QPACK 动态表的最大容量（字节） |
| `0x06` | `MAX_FIELD_SECTION_SIZE` | 头部段的最大大小 |
| `0x07` | `QPACK_BLOCKED_STREAMS` | 允许被 QPACK 阻塞的最大流数 |

注意 `0x02` 到 `0x05` 是保留的——它们对应 HTTP/2 的设置项（如 `ENABLE_PUSH`、`MAX_CONCURRENT_STREAMS` 等），在 HTTP/3 中被显式禁止。如果接收方在 SETTINGS 帧中看到这些 ID，必须以 `H3_SETTINGS_ERROR`（0x0109）终止连接。这是一个"切断退路"的设计：HTTP/3 不是 HTTP/2 的简单升级，不允许通过 SETTINGS 帧偷偷引入 HTTP/2 的语义。

SETTINGS 交换有一个重要特征：**它不是同步的**。双方独立发送各自的 SETTINGS 帧，不需要等对端的 SETTINGS 到达后才能发送自己的。这意味着在连接的最初几个 RTT 内，一端可能还没有收到对端的 SETTINGS，但已经开始发送请求了。RFC 9114 §7.2.4.2 允许这种"乐观"行为：在收到对端的 SETTINGS 之前，端点使用设置项的初始默认值发送消息。一旦 SETTINGS 到达，新值立即生效。

在 quicX 中，SETTINGS 的接收路径要经过一次"流类型发现"。对端的 Control Stream 到达时，QUIC 层只知道"来了一条新的单向流"——不知道它是 Control Stream、QPACK Stream 还是 Push Stream。quicX 的解决方案是先创建一个 `UnidentifiedStream`：它读取流的第一个 varint（流类型字节），然后根据类型值分发到对应的处理器：

```
新的单向接收流到达
  → 创建 UnidentifiedStream
  → 读取第一个 varint → stream_type
  → type = 0x00 → 创建 ControlReceiverStream
    type = 0x01 → 创建 PushReceiverStream（仅客户端）
    type = 0x02 → 创建 QpackEncoderReceiverStream
    type = 0x03 → 创建 QpackDecoderReceiverStream
    其他     → 忽略（RFC 9114 §6.2 要求不能因为未知流类型关闭连接）
```

当流类型被确认为 `0x00`（Control Stream）后，`ControlReceiverStream` 接管数据处理。它使用 `FrameDecoder` 解析帧——第一帧必须是 SETTINGS。解析出的设置参数最终回调到 `IConnection::HandleSettings()`，在这里完成三件事：检查是否包含被禁止的 HTTP/2 设置 ID、将对端的参数值与本端配置取最小值合并、标记 `settings_received_ = true`。

`settings_received_` 这个标记有实际意义。quicX 的 `ResponseStream` 在收到请求的 HEADERS 帧后，会先检查这个标记——如果对端的 SETTINGS 还没有到达，响应处理会被延迟。这是 RFC 9114 §4.1 的要求：端点在发送 SETTINGS 之前不应该处理请求。

至此，SETTINGS 交换完成。QPACK 动态表容量已确定、阻塞上限已确定——QPACK 子系统完全就绪。连接从"通道可用"升级为"**HTTP/3 完全就绪**"。

---

## 31.3 第一个请求：从头部编码到 DATA 传输

连接就绪后，第一个 HTTP 请求的完整旅程如下。

**客户端发送请求**。应用调用 `Client::DoRequest(request, handler)`。quicX 首先检查 `max_concurrent_streams` 限制——如果当前活跃的请求流已达上限，请求会被排队等待。检查通过后，调用 `quic_connection_->MakeStreamAsync(kBidi, callback)` 创建一条双向流。注意"Async"后缀：流创建是异步的，因为 QUIC 层的流额度可能不足，需要等待对端发来 `MAX_STREAMS` 帧。

流创建成功后，回调中构造 `RequestStream`。然后是发送序列：

1. **伪头部编码**：`PseudoHeader::EncodeRequest()` 把 `:method`、`:scheme`、`:authority`、`:path` 从 request 对象中提取出来，放在头部字段列表的最前面（RFC 9114 §4.3 要求伪头部必须在普通头字段之前）。

2. **QPACK 压缩**：`ReqRespBaseStream::SendHeaders()` 调用 `QpackEncoder::Encode()`，把头部字段列表压缩成字节。编码过程遵循第 30 章讲过的策略——先查静态表，再查动态表，未命中的用字面量编码。编码结果包含 Header Block Prefix（Required Insert Count + Base）和编码后的字段表示。

3. **封帧与发送**：压缩后的字节封装为 `HeadersFrame`（类型 `0x01`），写入 QUIC 双向流。如果有请求体，再构造一个或多个 `DataFrame`（类型 `0x00`）写入同一条流。最后，客户端关闭流的发送端（发送 FIN），表示请求发送完毕。

**服务端接收请求**。QUIC 层上报新的双向流后，`ServerConnection::HandleStream()` 创建 `ResponseStream` 并调用 `Init()`——这一步注册了 QUIC 流的读写回调。注册时使用 `weak_ptr`，防止流对象被销毁后回调仍然触发（这是第 18 章讲过的 use-after-free 防御模式）。

数据到达时，处理链路如下：

```
QUIC 流读回调 → ResponseStream::OnData()
  → FrameDecoder::DecodeFrames()     // 从字节流中解析帧
    → 帧类型 = HEADERS:
      → ReqRespBaseStream::HandleHeaders()
        → QpackEncoder::ReadHeaderPrefix()  // 读取 RIC 和 Base
        → QpackEncoder::Decode()            // QPACK 解码
        → 如果 RIC > 当前 InsertCount → 注册到 BlockedRegistry，等待
        → 解码成功 → PseudoHeader::DecodeRequest()  // 提取 method, path
        → ResponseStream::HandleHeaders()
          → 检查 settings_received_
          → IHttpProcessor::MatchRoute(method, path) → RouteConfig
          → handler->Handle(request, response)       // 应用回调
    → 帧类型 = DATA:
      → HandleData() → 积累请求体
      → 全部数据到齐后 → HandleResponse()
```

**服务端发送响应**。Handler 处理完毕后，`ResponseStream::SendResponse()` 执行：`PseudoHeader::EncodeResponse()` 编码 `:status` 伪头部 → QPACK 压缩 → 封装为 `HeadersFrame` 发出 → 如果有响应体，发出 `DataFrame` → 发送 FIN。

**客户端接收响应**。`RequestStream::OnData()` 收到响应的 HEADERS 帧后，QPACK 解码、提取 `:status` → 收到 DATA 帧后通过回调通知应用 → 收到 FIN 后请求完成。

整个链路涉及的组件串联起来就是：**应用层** → `PseudoHeader`（伪头部编解码）→ `QpackEncoder`（头部压缩/解压）→ `HeadersFrame` / `DataFrame`（帧封装）→ `FrameDecoder`（帧解析）→ `ReqRespBaseStream`（流级处理）→ `IRouter`（路由分发）→ `Handler`（应用回调）。每个组件在前三章中都已经独立拆解过——这里看到的是它们在一次真实请求中的**协作姿态**。

---

## 31.4 并发的风景：多条请求流与流控的交互

单条请求的路径清晰之后，把镜头拉远一步：多条请求并发运行时，画面变成什么样？

HTTP/3 的多路复用建立在 QUIC Stream 的独立性之上——每条请求流有自己的偏移量、自己的流控窗口、自己的丢包恢复。一条流的丢包不会阻塞另一条流的接收。这正是 QUIC 相比 HTTP/2 over TCP 的核心优势：没有传输层的队头阻塞。

但独立性不意味着没有交互。至少有两个维度的交互在并发场景下会显现出来：

**流控的背压传导**。每条 Request Stream 有自己的流级流控窗口（`MAX_STREAM_DATA`），同时所有流共享连接级额度（`MAX_DATA`）。当某条流发送数据过快，流级额度耗尽时，该流发出 `STREAM_DATA_BLOCKED` 信号、停止写入；当所有流的总发送量逼近连接级额度时，连接级 `DATA_BLOCKED` 信号触发，影响所有流。HTTP/3 层不直接操作流控——但它需要感知流控导致的"背压"。在 quicX 中，`ReqRespBaseStream::HandleSent()` 回调会收到实际发送的字节数和错误码：如果底层因为流控限制只发出了部分数据，HTTP/3 层会暂停上层的数据投递，等待下一次写可用通知。

**QPACK 的阻塞与解阻塞**。并发场景下 QPACK 的行为比单条请求复杂得多。编码端可能在 Stream A 的 HEADERS 帧中引用了动态表索引 62——这个条目是通过 Encoder Stream 插入的。解码端可能先收到了 Stream B 的 HEADERS 帧，Stream B 也引用了索引 62。如果 Encoder Stream 的数据已经到达，Stream B 的解码直接成功；如果还没到达，Stream B 被标记为"阻塞"，注册到 `BlockedRegistry`。

当 Encoder Stream 的数据终于到达、`QpackEncoder::DecodeEncoderInstructions()` 完成动态表更新后，`BlockedRegistry::NotifyAll()` 被调用——所有等待中的流被批量唤醒，重新尝试 QPACK 解码。这是一个"盲唤醒"策略：不检查哪条流具体等的是哪个插入，而是唤醒全部，让每条流自己判断条件是否满足。第 30 章已经分析过，这种设计在阻塞流数量不大时（受 `QPACK_BLOCKED_STREAMS` 上限约束），用简单性换取了正确性。

quicX 的连接级流管理用 `streams_`（`unordered_map<stream_id, shared_ptr<IStream>>`）维护所有活跃的 HTTP/3 流。收到帧时，通过 stream_id 快速定位到对应的流对象。`max_concurrent_streams`（默认 200）限制了同时活跃的请求流数量——超过限制的请求在客户端排队，等待现有流完成后再发起。

---

## 31.5 告别的仪式：GOAWAY 信号与优雅排空

连接总有终结的时候。HTTP/3 的关闭分两层：HTTP/3 层的 GOAWAY 和 QUIC 层的 CONNECTION_CLOSE。

**优雅关闭**从 GOAWAY 帧开始。RFC 9114 §5.2 规定，一端想要关闭连接时，在 Control Stream 上发送一个 `GOAWAY` 帧。这个帧只有一个字段：一个 Stream ID（从服务端发出时）或 Push ID（从客户端发出时），表示"此 ID 以及之后的请求/推送不会被处理"。

GOAWAY 的作用不是立即关闭连接，而是**宣告关闭意图**。收到 GOAWAY 后，对端不能在这条连接上发起新的请求（RFC 9114 §5.2 明确禁止），但已经在路上的请求——Stream ID 小于 GOAWAY 指定值的——仍然会被正常处理。这就是"排空"（draining）：让进行中的请求有机会完成，再真正关掉连接。

一端可以发送多个 GOAWAY 帧，但每次携带的 Stream ID 不能递增——只能递减或保持不变。这个约束确保了关闭范围只会收窄不会扩大：先说"100 号以后不处理"，后来可以改为"80 号以后不处理"，但不能反悔变成"120 号以后不处理"。quicX 的 `ControlServerReceiverStream` 实现了这个单调递减检查：如果新的 GOAWAY 的 Stream ID 大于之前收到的，立即以 `H3_ID_ERROR`（0x0108）终止连接。

排空完成后——所有进行中的请求都已完成——双方关闭 QUIC 连接。quicX 的 `IConnection::Close(error_code)` 在此时被调用：如果 `error_code` 为 0，调用 `quic_connection_->Close()` 执行优雅的 QUIC 关闭（发送 `CONNECTION_CLOSE` 帧，错误码 `H3_NO_ERROR` 0x0100）；如果 `error_code` 非零，调用 `quic_connection_->Reset()` 立即终止。

GOAWAY 是 HTTP/3 层的"预告"，CONNECTION_CLOSE 是 QUIC 层的"执行"——两者不矛盾，而是层次不同。GOAWAY 给应用层一个"准备关闭"的缓冲窗口；CONNECTION_CLOSE 是传输层的最终裁决。

**异常关闭**不走 GOAWAY 路径。如果关键流（Control Stream 或 QPACK Stream）被意外关闭，RFC 9114 §6.2.1 要求立即以 `H3_CLOSED_CRITICAL_STREAM`（0x0104）终止连接——不需要排空，因为失去基础设施流的连接已经无法正常运转。其他连接级错误（如收到被禁止的 HTTP/2 设置 ID、第二个 SETTINGS 帧等）也直接触发 CONNECTION_CLOSE。

quicX 的 `Client::Close()` 有一个实用的细节：关闭所有 HTTP/3 连接后，不是立即销毁 QUIC 层，而是启动一个 1 秒的延迟定时器，之后才调用 `quic_->Destroy()`。这 1 秒给了在途的 CONNECTION_CLOSE 帧和可能还在路上的最后几个响应一个到达的机会——是"优雅"的最后一英里。

---

## 31.6 quicX 的 HTTP/3 连接全景：从 Connection 到 Stream 的协作

以上五节走完了一条 HTTP/3 连接的完整时间线。现在把这条时间线浓缩为一张全景图。

quicX 的 HTTP/3 层由三个层次的组件构成：

**连接层**。`ClientConnection` 和 `ServerConnection` 继承自 `IConnection`，是 HTTP/3 连接的总控制器。它持有 QUIC 连接句柄、`QpackEncoder`、`BlockedRegistry`，以及 `streams_` 映射表。连接层负责初始化三条基础设施流、分发新到达的流、调度流的清理和销毁。

**流层**。这是组件最密集的一层。按职责可以分成四类：

| 类别 | 流类 | 职责 |
|------|------|------|
| 控制流（发送） | `ControlSenderStream`、`ControlClientSenderStream` | 发送 SETTINGS、GOAWAY、MAX_PUSH_ID |
| 控制流（接收） | `ControlReceiverStream`、`ControlServerReceiverStream` | 接收 SETTINGS、GOAWAY，触发参数生效 |
| QPACK 流 | `QpackEncoderSenderStream`、`QpackEncoderReceiverStream`、`QpackDecoderSenderStream`、`QpackDecoderReceiverStream` | 动态表指令传输与确认反馈 |
| 数据流 | `RequestStream`（客户端）、`ResponseStream`（服务端），共同基类 `ReqRespBaseStream` | 请求/响应的编解码和传输 |

还有一个特殊角色：`UnidentifiedStream`。它是所有新到达单向流的"接待员"——读取流类型字节后把流分配到上面四类中的某一类，自身随即退场。

**应用层**。`Client` 和 `Server` 是面向用户的入口。`Client` 维护 `conn_map_`（host → ClientConnection），管理连接复用和请求排队。`Server` 实现 `IHttpProcessor` 接口，提供路由匹配（`MatchRoute`）和中间件链，把到达的请求分发给应用注册的 Handler。

一条 HTTP/3 连接的完整生命周期，用时间线摘要如下：

```
时刻 0    QUIC 握手完成 → handshake_done_cb_
          ├─ 创建 ClientConnection / ServerConnection
          ├─ 创建 Control Stream + QPACK Encoder/Decoder Stream
          └─ 发送 SETTINGS 帧（Control Stream 首帧）

时刻 1    对端 SETTINGS 到达 → UnidentifiedStream 发现 type=0x00
          → ControlReceiverStream 接管 → 解析 SETTINGS → 参数合并
          → settings_received_ = true → QPACK 完全就绪

时刻 2    第一个请求 → MakeStreamAsync(kBidi)
          → RequestStream 创建 → QPACK Encode → HeadersFrame + DataFrame → FIN
          → 服务端: ResponseStream 创建 → QPACK Decode → Router → Handler
          → 服务端: SendResponse → QPACK Encode → HeadersFrame + DataFrame → FIN
          → 客户端: 收到响应 → QPACK Decode → 回调应用

时刻 3..N 并发请求 → 多条 Request/Response Stream 同时活跃
          → QPACK 可能阻塞 → BlockedRegistry
          → Encoder Stream 数据到达 → NotifyAll → 批量解阻塞
          → 流控背压 → DATA_BLOCKED / STREAM_DATA_BLOCKED → MAX_DATA 恢复

时刻 T    GOAWAY → Control Stream 发出 → 对端停止新请求
          → 已有请求排空完成 → Close(0) → CONNECTION_CLOSE(H3_NO_ERROR)
          → 1 秒延迟 → Destroy
```

流对象的生命周期管理有一个工程细节值得提及。流完成时，不是立即从 `streams_` 中删除——因为删除操作可能发生在流的回调栈内部，直接删除会导致 use-after-free。quicX 的做法是"延迟销毁"：把完成的流从 `streams_` 移到 `streams_to_destroy_` 缓冲区，由 100ms 周期定时器 `CleanupDestroyedStreams()` 统一回收。这与第 18 章讲过的异步回调生命周期策略一脉相承。

回头审视卷六四章的递进弧线：第 28 章画出地图（帧体系 + 流分类 + 控制面），第 29 章走进数据面（请求映射 + 错误语义），第 30 章拆开引擎（QPACK 头压缩的设计与实现），第 31 章装回系统（一条连接的完整生命周期）。从零件到系统，从静态结构到运行时画面——HTTP/3 连接可以正确运转了。

但"正确运转"不等于"可以上生产"。一条连接在野外遇到丢包风暴时，你能看到 QPACK 的阻塞计数吗？拥塞窗口骤降时，你能还原事故现场吗？日志里几千行异步回调交错在一起时，你能分辨哪一行属于哪条连接吗？这些问题的答案，属于下一卷。
