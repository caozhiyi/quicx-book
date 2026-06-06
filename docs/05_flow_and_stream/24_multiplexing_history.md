# 24. 从队头阻塞到传输层并发：Stream 为什么是 QUIC 的另一半身体

一条连接可靠了、能控速了——但它只是一根管道。管道里跑的是什么？一段数据和另一段数据之间有没有边界？一段数据丢了，另一段数据要不要陪着等？

这些问题指向 QUIC 协议中和连接几乎同等重要的另一个核心抽象：**Stream**。

---

## 24.1 从串行到伪并发：HTTP/1.1 和 HTTP/2 为什么都没彻底解决并发问题

HTTP/1.1 的问题是纯粹的串行：一条连接上的请求和响应必须排队，前一个没完成后一个就得等着。浏览器用"多开连接"来缓解（Chrome 每个域名最多 6 条），但这只是拿资源换时间——6 条连接意味着 6 倍握手开销、6 份独立的拥塞窗口冷启动。

HTTP/2 做了一件漂亮的事：在一条 TCP 连接上引入了应用层的 Stream 概念——每个 Stream 有独立的 ID，请求和响应被拆成帧交错传输，不同 Stream 的帧可以在同一条连接上并行。这确实消灭了应用层的队头阻塞。

但问题出在下一层：**TCP 只看到一条连续字节流，不认识 HTTP/2 的 Stream ID**。所有 Stream 的帧在 TCP 的序号空间里混排成一条单一的字节流。一旦某个字节段丢失，TCP 必须等待重传完成才能把后续字节交付给上层——即使那些后续字节属于完全不同的 Stream，即使它们已经完好地躺在接收端的缓冲区里。根源在于 TCP 的序号身兼三职（确认、恢复、交付），确认没完成的事拖住了交付已经完成的事。

HTTP/2 的应用层多路复用和 TCP 的传输层单字节流之间存在一个根本性的视角错位：上面觉得是多条独立的路，下面只看到一条必须有序的线。这种错位不是 HTTP/2 设计偷懒，也不是 TCP 实现不够好——是层次本身的限制。**只要多路复用停留在应用层，就永远摆脱不了传输层只有一条字节流的结构性约束。**

QUIC 的回答是：把多路复用做进传输层。不是在 TCP 之上再贴一层抽象，而是在传输层本身就支持多条独立的有序字节流——每条流有自己的 ID、自己的偏移量空间、自己的丢包重传边界。一条流丢了包，只有那条流需要等待重传，其他流完全不受影响。

这就是 QUIC 的 Stream——传输层原生的、轻量的、独立的有序字节流。

---

## 24.2 QUIC 怎样把多路复用嵌进传输层：Stream 的四条设计原语

RFC 9000 §2 给出了 Stream 的定义：

> "Streams in QUIC provide a lightweight, ordered byte-stream abstraction to an application."

这句话里的"轻量级"和"有序字节流"都很关键：Stream 不是一个重量级的对象（它不需要额外的握手来创建），但它拥有完整的字节流语义（数据有顺序、有偏移、有终止）。QUIC 的 Stream 设计可以归纳为四条原语。

**原语一：Stream ID 编码规则——一个数字压缩三维信息。**

每条 Stream 有一个唯一的 Stream ID，用变长整数编码（最大可达 2^62-1）。但 Stream ID 不只是一个编号——它的最低两个比特同时编码了两条额外信息：

| 低 2 位 | 发起方 | 方向 | 含义 |
|---------|--------|------|------|
| 0x00 | 客户端 | 双向 | 客户端发起的双向流 |
| 0x01 | 服务器 | 双向 | 服务器发起的双向流 |
| 0x02 | 客户端 | 单向 | 客户端发起的单向流 |
| 0x03 | 服务器 | 单向 | 服务器发起的单向流 |

这意味着：收到一个 Stream ID，不需要查表就能知道它是谁发起的、是双向还是单向的。协议解析器、状态机选择器、流控逻辑，都可以直接从 ID 的低两位得到这些关键信息。

同一类型的流的 ID 从最小值开始，按数值严格递增。客户端发起的双向流依次是 0、4、8、12……服务器发起的双向流是 1、5、9、13……步长都是 4，因为低两位被类型编码占了。RFC 9000 §2.1 明确要求：端点绝不能重用一个 Stream ID。一条流创建后就永远不会被"回收再利用"——流的出生和死亡由 ID 的单调递增天然排序。

**原语二：双向流与单向流的语义差异——不是"省一个方向"那么简单。**

双向流（Bidirectional Stream）两端对等：客户端和服务器都可以在这条流上读写数据。HTTP/3 的请求-响应就映射到双向流上——客户端写请求头和请求体，服务器写响应头和响应体。

单向流（Unidirectional Stream）只有发起方能写，对端只能读。这不是"双向流砍掉一半"的偷懒设计，而是表达了完全不同的通信语义：HTTP/3 的控制流（SETTINGS、GOAWAY）和 QPACK 编解码流都是单向的——它们是"通知"而不是"对话"。Server Push 也走单向流——服务器主动推数据给客户端，不需要客户端先说话。

双向流和单向流的区别不只是"能不能写"，更重要的是**状态机的完整性不同**：双向流有独立的发送侧状态机和接收侧状态机，单向流只有其中一个。这一点会在第 25 章状态机那里展开。

**原语三：流的独立性——每条流有自己的偏移量空间。**

每条 QUIC Stream 维护自己独立的 Offset。STREAM 帧携带的三元组 `(Stream ID, Offset, Length)` 精确定位了这段数据在哪条流的哪个位置。接收端根据 Offset 把数据放到对应流的正确位置，如果某段 Offset 缺失（丢包了），只有这条流需要等待重传——其他流的 Offset 空间完全不受影响。

第 13 章把这个机制叫做"交付层独立于确认层"：确认层（Packet Number）管"这个包到了没"，交付层（Stream Offset）管"这段数据放在流的什么位置"。两者各自演进，互不拖拽。

这就是 QUIC 消除跨流队头阻塞的结构基础——不是靠调度算法，而是靠每条流拥有独立的偏移量空间这个设计原语。

**原语四：流的并发性——同一连接可以同时承载成百上千条流。**

QUIC 的 Stream ID 最大可达 2^62-1，理论上一条连接可以创建天文数字的流。实际的上限由流控决定——对端通过 `max_streams` 传输参数和 `MAX_STREAMS` 帧来限制同时存在的流数量（第 26 章会展开）。

流的创建是隐式的：发送端只需要发送一个携带新 Stream ID 的 STREAM 帧，这条流就诞生了，不需要专门的"创建流"握手。轻量级的创建方式让"一条连接上开几百条流"变成了低成本的操作。

---

## 24.3 Stream 不是连接的附属标签：一等公民意味着什么

QUIC 之前，也有协议尝试在传输层做多流。SCTP（Stream Control Transmission Protocol）在一个关联（association）上支持多条 Stream，但 SCTP 的 Stream 更像一个消息的分类标签——它没有独立的状态机，没有独立的生命周期管理，不能被单独终止或重置。

QUIC 的 Stream 不一样。RFC 9000 §2.4 列出了 Stream 必须支持的操作集：发送端可以写入数据、可以结束流（发 FIN）、可以重置流（发 RESET_STREAM）；接收端可以读取数据、可以中止读取（发 STOP_SENDING）。这些操作作用于单条流，不影响连接上的其他流。

**独立生命周期。** Stream 可以独立地打开、传输数据、关闭——不需要等连接关闭才释放资源。一条流发完了所有数据，发送端发一个带 FIN 位的 STREAM 帧，这条流的发送侧就进入终止状态，而连接上的其他流继续运转。这意味着 QUIC 可以支持更灵活的通信模式：客户端发完请求后关闭发送端，但保持接收端打开等服务器慢慢响应；服务器在单向流上主动推送数据，不需要客户端先发起请求。

**独立终止语义。** Stream 有三种独立的终止动作：FIN 是"我数据发完了"（正常结束），RESET_STREAM 是"我不发了，你可以丢掉已收到的数据"（异常终止），STOP_SENDING 是接收端告诉发送端"别发了，我不要了"（中止读取）。这三种动作各自表达不同的语义——FIN 是合作性的，RESET_STREAM 是单方面的，STOP_SENDING 是反向的请求。它们都是流级别的动作，不影响连接。

**连接是容器，Stream 是内容。** 连接和 Stream 的职责划分非常清晰：

| 职责 | 连接（Connection） | Stream |
|------|-------------------|--------|
| 加密 | 连接级密钥，Key Update 时所有流一起切换 | 继承连接的加密保护 |
| 丢包检测 | Packet Number 级别的确认和判丢 | 不直接参与（由连接的确认层驱动） |
| 流控 | 连接级总额度（MAX_DATA） | 每条流的独立额度（MAX_STREAM_DATA） |
| 生命周期 | 连接建立、保持、关闭 | 流创建、传输、结束（独立于连接） |
| 路径迁移 | Connection ID 支撑路径迁移 | 流跟随连接迁移，无感知 |

连接坏了，所有流都死——这是容器的语义。但一条流死了，连接和其他流不受影响——这是一等公民的语义。QUIC 的许多后续机制都围绕 Stream 重新组织：HTTP/3 的请求-响应映射到 Stream，流控必须区分连接级和流级，背压信号必须能够精确地指向特定的流。

卷五不是在讲一个附属功能，而是在讲 QUIC 的另一半身体。连接是骨架，Stream 是血脉。

---

## 24.4 quicX 的 Stream 继承体系：一张类图背后的设计取舍

前面三节讲的是协议定义。现在看看 quicX 如何用 C++ 的继承体系把这些设计原语映射为代码结构。

quicX 在 `src/quic/stream/` 目录下组织了整套 Stream 实现。类继承关系如下：

```
IQuicStream (对外接口基类)
    │
    ├── IStream (核心内部基类)
    │       │
    │       ├── CryptoStream (握手专用流)
    │       │
    │       ├── SendStream ──► IQuicSendStream
    │       │
    │       ├── RecvStream ──► IQuicRecvStream
    │       │
    │       └── BidirectionStream (菱形继承 SendStream + RecvStream)
    │                              ──► IQuicBidirectionStream
```

**IStream 是所有流的内部基类。** 它定义了流必须回答的两个核心问题：收到一个帧该怎么处理（`OnFrame`），以及轮到我发送时该产生什么数据（`TrySendData`）。`TrySendData` 返回一个四值枚举——成功、失败、包满了需要单独发送、被流控阻塞——这四种结果精确地对应了发送调度时的四种场景：

```cpp
enum class TrySendResult {
    kSuccess = 0,              // 生成数据完成
    kFailed = 1,               // 生成数据失败，从活跃列表移除
    kBreak = 2,                // 包满了，需要先发出去再继续
    kFlowControlBlocked = 3,   // 被流控阻塞，保留在活跃列表
};
```

IStream 还持有三个回调函数：`active_send_cb_` 把自己加入活跃发送列表，`stream_close_cb_` 通知 StreamManager 自己已关闭，`connection_close_cb_` 触发连接级别的错误关闭。一条流通过这三个回调和外部世界交互，不需要直接持有 StreamManager 或 Connection 的指针——这是依赖注入的设计。

**SendStream 代表发送侧。** 它持有独立的发送状态机 `StreamStateMachineSend`、发送缓冲区 `send_buffer_`、当前发送偏移 `send_data_offset_`、对端流控上限 `peer_data_limit_`。外部通过 `Send()` 写入数据，内部通过 `TrySendData()` 在发送调度时把缓冲区里的数据组装成 STREAM 帧。当收到对端的 MAX_STREAM_DATA 帧时，`OnMaxStreamDataFrame()` 更新流控上限；当收到 STOP_SENDING 帧时，`OnStopSendingFrame()` 处理对端的中止请求。

**RecvStream 代表接收侧。** 它持有独立的接收状态机 `StreamStateMachineRecv`、接收缓冲区、期望的下一个偏移 `except_offset_`、本地流控窗口 `local_data_limit_`。收到 STREAM 帧时，`OnStreamFrame()` 根据 Offset 把数据放到正确位置——如果 Offset 连续了，立刻通过 `recv_cb_` 回调交付给应用层；如果还有洞，先存入 `out_order_frame_` 乱序缓存等待补齐。收到 RESET_STREAM 帧时，`OnResetStreamFrame()` 处理对端的单方面终止。

**BidirectionStream 菱形继承 SendStream 和 RecvStream。** 这个继承关系直接映射了协议原语：双向流不是"一个流两个方向"，而是"两台独立的状态机（发送侧+接收侧）被同一个 Stream ID 绑在一起"。C++ 的 virtual 继承确保 IStream 基类只有一份实例。`BidirectionStream` 增加了一个 `CheckStreamClose()` 方法——只有当发送侧和接收侧都进入终止状态时，双向流才算真正关闭。

**CryptoStream 是个特例。** 它不参与 SendStream/RecvStream 的继承体系，而是直接继承 IStream。CryptoStream 用于传输 TLS 握手数据（CRYPTO 帧），和普通数据流有一个关键区别：它按加密级别（Initial / Handshake / 1-RTT）维护独立的读写缓冲区和偏移。这是因为握手过程中加密级别会升级，不同级别的 CRYPTO 数据必须各自独立排序。

```cpp
// CryptoStream 为每个加密级别维护独立的缓冲区
std::shared_ptr<common::MultiBlockBuffer> read_buffers_[kNumEncryptionLevels];
uint64_t next_read_offset_[kNumEncryptionLevels];
std::shared_ptr<common::MultiBlockBuffer> send_buffers_[kNumEncryptionLevels];
uint64_t send_offset_[kNumEncryptionLevels];
```

CryptoStream 还有一个 `ResetForRetry()` 方法——当服务端发回 Retry 包要求客户端重新握手时，Initial 级别的缓冲区需要清空重来。

这套继承体系的设计取舍很明确：每个类严格对应一种 Stream 原语。SendStream 对应"只能发"，RecvStream 对应"只能收"，BidirectionStream 对应"既发又收"，CryptoStream 对应"握手专用"。你不会在代码里看到一个"通用 Stream 类"通过配置参数来区分方向——方向的差异在编译期就通过类型系统固化了。

---

## 24.5 Stream 的 ID 编码：两个比特如何决定一条流的身份

24.2 节讲了 Stream ID 编码的协议规则，这一节看看 quicX 如何实现它。

quicX 的 `StreamIDGenerator` 类负责按 RFC 9000 §2.1 的规则生成 Stream ID。它的核心方法只有一个：

```cpp
uint64_t StreamIDGenerator::NextStreamID(StreamDirection direction) {
    uint64_t next_stream = 0;
    switch (direction) {
        case StreamDirection::kBidirectional:
            next_stream = cur_bidirectional_id_++;
            break;
        case StreamDirection::kUnidirectional:
            next_stream = cur_unidirectional_id_++;
            break;
    }
    // 序号左移 2 位，低 2 位填入方向和发起方
    next_stream = next_stream << 2 | (direction | starter_);
    return next_stream;
}
```

`starter_` 在构造时由角色（客户端 = 0x0，服务器 = 0x1）决定。`direction` 是 0x0（双向）或 0x2（单向）。两者按位或之后填入 ID 的低两位——这就是 RFC 9000 Table 1 的编码规则在 C++ 里的直接映射。

以客户端为例：

- 第一条双向流：`(0 << 2) | (0x0 | 0x0) = 0`
- 第二条双向流：`(1 << 2) | (0x0 | 0x0) = 4`
- 第一条单向流：`(0 << 2) | (0x2 | 0x0) = 2`
- 第二条单向流：`(1 << 2) | (0x2 | 0x0) = 6`

以服务器为例：

- 第一条双向流：`(0 << 2) | (0x0 | 0x1) = 1`
- 第二条双向流：`(1 << 2) | (0x0 | 0x1) = 5`
- 第一条单向流：`(0 << 2) | (0x2 | 0x1) = 3`

四种流类型的 ID 序列恰好交替编织：0, 1, 2, 3, 4, 5, 6, 7……每个数字都唯一地对应一种类型和一个序号。

`StreamIDGenerator` 还提供了 `PeekNextStreamID()` 方法——只预览下一个 ID 而不递增计数器。这个方法在创建流之前用来检查是否会超出对端的 `max_streams` 限制：先 peek 一下，如果超限就不创建，避免浪费 ID。ID 一旦用了就不能回收（RFC 9000 §2.1 明确禁止重用），所以"先看后用"的谨慎是有必要的。

反向解码同样简单。静态方法 `GetStreamDirection()` 通过 `id & 0x2` 一步判断方向：

```cpp
StreamIDGenerator::StreamDirection StreamIDGenerator::GetStreamDirection(uint64_t id) {
    if (id & StreamDirection::kUnidirectional) {
        return StreamDirection::kUnidirectional;
    }
    return StreamDirection::kBidirectional;
}
```

发起方判断用 `id & 0x1`：0 是客户端，1 是服务器。这意味着 quicX 在收到一个 STREAM 帧时，解析器不需要查任何映射表，只用两次位运算就能知道这条流是谁发起的、什么方向——然后直接选择对应的处理路径。

Stream ID 的单调递增还有一个重要的副作用：**它天然排序了流的"出生顺序"**。如果你收到一个 ID 为 20 的客户端双向流的 STREAM 帧，你就知道 ID 为 0、4、8、12、16 的五条客户端双向流一定已经被创建过了（即使你还没收到它们的数据帧）。RFC 9000 §2.1 规定，收到一个更高 ID 的流时，所有中间 ID 的流也隐式地被打开了。这让流的创建具有了"序列化保证"——不会出现"第 6 条流到了但第 3 条流还没创建"的混乱状态。

---

## 24.6 连接只是舞台，流才是演员

走到这里，Stream 的外观已经展开了：

- **为什么需要它**：多路复用必须下沉到传输层，TCP 的单字节流模型无法表达"这个丢包只和某条流有关"
- **它长什么样**：四条设计原语——ID 编码压缩三维信息、双向/单向表达不同通信语义、独立偏移消除跨流阻塞、轻量级创建支撑高并发
- **在 quicX 里怎么表达**：IStream/SendStream/RecvStream/BidirectionStream 的继承体系把原语固化为类型系统，StreamIDGenerator 把编码规则变成一行位运算

但"有独立身份"不等于"有完整的生命规则"。一条流从出生到结束，到底经历了哪些状态？发送侧说"我发完了"和接收侧说"我收全了"，是同一件事吗？RESET_STREAM 和 STOP_SENDING 为什么不是同义词？发送侧和接收侧的视角为什么必须用两台独立的状态机来描述？

下一章正式打开 Stream 的生命周期。

---
