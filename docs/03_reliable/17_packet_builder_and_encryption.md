# 17. 发包管线：PacketBuilder 与加密层调度

第 16 章解决了"恢复什么"——丢了的包不会被原样重发，而是从发送缓冲区里取出相同语义的数据，装进全新的包发出去。但这句话藏着一个前提：你得先把那个"全新的包"造出来。

造一个 QUIC Packet 远比往 TCP socket 里 `write()` 一段字节流复杂。TCP 只需要把数据追加到发送缓冲区，由内核帮你分段、编号、加密（如果走 TLS）。QUIC 把这些事全搬到了用户态：三个独立编号的 Packet Number Space、三套不同的 AEAD 密钥、1200 字节的最小数据报约束、多个包合并进同一 UDP 数据报的 Coalescing 优化——每一条规则都在约束"这个包该怎么拼"。

这就是本章要回答的问题：那些等待发送、等待恢复、等待确认的语义，最终是怎样被组装成一个个可以真正交给 UDP 发出去的 Packet 的？

本章的路线是：先讲帧优先级调度（17.1–17.2），再讲加密级别对发送路径的结构性约束（17.3），接着展开 Padding、Token、Coalescing 三个工程约束和一个完整的组包例子（17.4），然后落到 quicX 的实现（17.5），最后做卷三的阶段性收束（17.6）。

---

## 17.1 从"该发什么"到"真正发出去"：发送路径中间隔着什么

"知道该发什么"和"真正能发出去"之间，隔着一条很长的工程鸿沟。这条鸿沟由四道约束构成。

第一道约束是容量。单个 QUIC Packet 的 payload 空间受限于 UDP 数据报的 MTU——一般在 1200 到 1472 字节之间。你不能把所有待发的 Frame 塞进一个包，必须决定哪些 Frame 放这个包、哪些等下一轮。

第二道约束是空间隔离。Initial、Handshake、Application 三个 Packet Number Space 各自独立编号、各自使用不同的 AEAD 密钥（RFC 9000 §12.3）。一个 Initial 帧和一个 STREAM 帧不能被装进同一个 Packet——它们属于不同的加密级别。

第三道约束是帧类型限制。并非所有 Frame 都能出现在所有级别的包里。RFC 9000 §12.4 明确规定，Initial 和 Handshake 包只允许携带 ACK、CRYPTO、PADDING、PING、CONNECTION_CLOSE 五种帧。STREAM、MAX_DATA 这类帧只能出现在 Application（1-RTT）包中。这条规则直接决定了发送管线在过滤帧时必须感知当前的加密级别。

第四道约束是对端状态。如果握手还没完成，对端不具备解密 1-RTT 包的能力，你就不能发 Application 包。发送路径必须实时感知连接的握手进度。

四道约束叠加在一起，使得 QUIC 的发送路径变成了一个调度与装配的过程：决定"谁先说"（优先级），判断"能不能说"（加密级别），控制"说多少"（容量），正确地"组装起来"（Packet 构造）。这就是 quicX 需要 `SendManager`、`PacketBuilder`、`EncryptionLevelScheduler` 三个模块协作的原因——如果把这些逻辑写成一把梭的代码，每加一条新规则都会在发送路径里撕开一道口子。

---

## 17.2 谁先上车：控制帧、流数据与包容量的博弈

发送路径面对的最现实问题不是"怎么拼包"，而是"让谁先上"。单个 Packet 的 payload 空间有限，每次发包都是一道选择题：控制帧想上车，流数据也想上车，恢复中的语义想上车，全新数据也想上车——但座位就那么几个，让谁先上？

答案藏在协议设计的优先级排序里。

第一优先级是 ACK。ACK 是可靠性的根基——没有 ACK，发送端不知道哪些包到了、哪些包丢了，后续的丢包探测和重传全部无法启动。因此，当发送端准备发包时，如果有待发的 ACK Frame，它会被优先塞进 Packet。在 quicX 的实现里，这个优先级体现得很直接：`BaseConnection::TrySend()` 在收集完所有控制帧之后，会把 ACK 帧插到帧列表的最前面——确保它第一个被编码进包。

第二优先级是控制帧。MAX_DATA、MAX_STREAM_DATA 告诉对方"你可以继续发数据了"；PING 用来保活和触发 ACK；PATH_CHALLENGE、PATH_RESPONSE 用来探测路径状态。这些帧不携带应用数据，但它们维系着连接的生命体征——如果它们没发出去，连接可能会卡住。

第三优先级是恢复中的语义。丢了的包需要重传（第 16 章的核心结论）。如果某个 STREAM Frame 丢了，发送端需要尽快重传它的语义。恢复中的语义通常比全新数据更紧急——因为已经"欠"了对方一些数据。

最后才是全新的应用数据。一个刚写入的 STREAM Frame，如果没有丢包压力，可以等下一轮发送机会。

但优先级调度还受到一个硬约束：帧类型限制。RFC 9000 §12.4 规定，不同加密级别的包只允许携带特定类型的帧：

```
┌──────────────────────┬─────────────────────────────────────────┐
│    Packet 类型        │         允许的帧类型                      │
├──────────────────────┼─────────────────────────────────────────┤
│ Initial              │ ACK, CRYPTO, PADDING, PING,             │
│                      │ CONNECTION_CLOSE                        │
├──────────────────────┼─────────────────────────────────────────┤
│ Handshake            │ ACK, CRYPTO, PADDING, PING,             │
│                      │ CONNECTION_CLOSE                        │
├──────────────────────┼─────────────────────────────────────────┤
│ 0-RTT                │ STREAM, PADDING, PING,                  │
│                      │ MAX_DATA, MAX_STREAM_DATA, ...          │
│                      │ （不允许 ACK）                             │
├──────────────────────┼─────────────────────────────────────────┤
│ 1-RTT (Application)  │ 所有帧类型                                │
└──────────────────────┴─────────────────────────────────────────┘
```

这意味着，就算有一堆 STREAM 帧在排队等发，如果当前只能构造 Initial 包，发送管线也必须把它们全部跳过——只带走 ACK、CRYPTO 和 PADDING。这不是实现上的偷懒，而是协议层面的硬规则。quicX 的 `SendManager::GetPendingFrames()` 就做了这个过滤：当加密级别不是 Application 时，只取走 ACK、CRYPTO、PADDING、PING、CONNECTION_CLOSE 五种帧，其余帧留在队列里等下一轮。

发送管线的微妙之处正在于此：它不只是序列化——把 Frame 变成字节流塞进 Packet。它更是调度——在有限的容量约束和帧类型限制下，决定谁先上路、谁必须等待。

---

## 17.3 不同的门，不同的钥匙：加密级别切换与发送顺序

发送路径不仅要回答"谁先上车"，还要回答一个更根本的问题：这辆车能不能开？能不能开，取决于当前手里有哪些密钥。

QUIC 的三个 Packet Number Space——Initial、Handshake、Application——各自使用不同的 AEAD 密钥（RFC 9001 §5）。发送端在发包时，必须清楚地知道当前有哪些密钥可用：

- 握手早期：只有 Initial 密钥，只能发 Initial 包。
- 握手中期：有了 Initial 和 Handshake 两把密钥，可以发两种包，但 Application 包还是发不了。
- 握手完成后：三把密钥齐全，所有类型的包都可以发。

密钥的获取是渐进式的——每完成一步 TLS 握手，就多解锁一个加密级别。这种渐进式解锁直接塑造了发送路径的结构：发送管线必须在每次发包前查询"当前最高可用级别是什么"，然后决定构造哪种类型的包。

更值得注意的是多级别并存时的发送顺序问题。在握手推进的过程中，同一时刻可能有多个级别都有数据待发。比如，服务端刚收到 ClientHello，它需要同时发 Initial ACK（确认收到 ClientHello）和 Handshake 包（携带 ServerHello 的 CRYPTO 帧）。这时候该先发哪个？

答案是：低级别优先。理由很实际——如果对端还卡在 Initial 阶段等你的 ACK，你先发一个 Handshake 包过去它根本解不了。quicX 的 `EncryptionLevelScheduler::GetNextSendContext()` 就实现了这个逻辑：当检测到低级别（如 Initial 或 Handshake）有未发送的 ACK 时，即使当前已经进入了更高的加密级别，也会优先回退到低级别去发 ACK——这就是"跨级别 ACK"调度。

这种调度的优先级排序是：

1. 跨级别 ACK（低级别有未确认的包需要 ACK）
2. 路径探测（PATH_CHALLENGE/PATH_RESPONSE，必须在 1-RTT 包中发送）
3. 0-RTT 早期数据（客户端在 Initial 之后、握手完成之前发送的应用数据）
4. 当前加密级别的正常数据

密钥还有一个生命周期约束：当握手完成、双方确认不再需要某个级别的密钥时，该级别的密钥会被丢弃（RFC 9001 §4.9）。丢弃 Initial 密钥后，即使有 Initial 级别的 ACK 待发，发送管线也无能为力——密钥已经不在了。quicX 在跨级别 ACK 调度时会检查密钥是否仍然存在，如果已丢弃就直接跳过。

发送路径不是简单的"把 Frame 装进 Packet"——它还受加密级别的约束。不同的门需要不同的钥匙；没有钥匙，门就打不开。

---

## 17.4 不是拼出来就完了：Padding、Token、Coalescing 带来的工程约束

Packet 构造不只是往包里塞 Frame。在帧被选好、加密级别确定之后，还有三个工程约束等在前面：Padding、Token、Coalescing。

**Padding：不是每个包都要填充，但 Initial 数据报必须**

RFC 9000 §14.1 规定：承载 Initial 包的 UDP 数据报至少为 1200 字节。注意，这个约束的对象是 UDP 数据报（datagram），不是 QUIC Packet 本身。如果一个 UDP 数据报只包含一个 Initial 包，而那个包的实际内容不足 1200 字节，发送端就需要用 PADDING 帧把它撑到 1200 字节。

为什么？这是一个反放大攻击的设计。如果攻击者伪造源地址发一个很小的 Initial 包，服务端可能回复一个大得多的 Handshake 响应——形成流量放大。1200 字节的下限确保了攻击者至少要付出与响应同等量级的带宽成本。

Padding 还有一个次要用途：混淆包长度，对抗基于流量分析的攻击。不过这更多是可选的安全增强，而非协议强制要求。

在 quicX 的 `PacketBuilder::BuildDataPacket()` 中，当加密级别为 `kInitial` 且 `add_padding` 标志为 true 时，构建器会计算当前包大小与 1200 字节的差值，创建一个对应大小的 `PaddingFrame` 补齐。

**Token：来自 Retry 或 NEW_TOKEN，不是 Version Negotiation**

客户端在首次连接或地址变化后，可能会收到服务端的 Retry 包，其中携带一个 Token。客户端在重新发送 Initial 包时，必须把这个 Token 原样放进包头的 Token 字段（RFC 9000 §8.1）。Token 也可能来自之前连接中服务端通过 NEW_TOKEN 帧下发的令牌——客户端可以在新连接的 Initial 包中携带它，以跳过地址验证。

Token 不是 Frame，它是 Initial 包头的一个独立字段。发送路径需要知道"当前有没有 Token"，如果有，就把它编码进 Initial 包的头部。在 quicX 中，Token 存储在 `SendManager` 的 `token_` 成员里，构建 `DataPacketContext` 时传给 `PacketBuilder`。

**Coalescing：同一个 UDP 数据报里装多个不同级别的包**

RFC 9000 §12.2 允许把多个 QUIC Packet 合并进同一个 UDP 数据报发送。接收端依次解析数据报中的每个包，用各自的密钥解密。这就是 Coalescing。

Coalescing 有两个约束。第一是容量约束：合并后的总长度不能超过 UDP 数据报的 MTU 限制。第二是格式约束：长头包（Long Header，即 Initial、Handshake、0-RTT）必须排在短头包（Short Header，即 1-RTT）前面。原因很直接——长头包有 Length 字段，接收端可以通过 Length 字段知道当前包在哪里结束、下一个包从哪里开始；而短头包没有 Length 字段，接收端只能假设短头包占据了数据报的全部剩余空间。所以短头包只能放在最后。

用一个握手期的真实场景来看 Coalescing 的效果。客户端发送初始连接请求时，一个 UDP 数据报的结构可能是这样的：

```
┌─────────────────────── UDP Datagram (1200 bytes) ───────────────────────┐
│                                                                         │
│  ┌─── Initial Packet ─────────────────────────────────────────────┐    │
│  │ Long Header: Version, DCID, SCID, Token                       │    │
│  │ Packet Number: 0                                               │    │
│  │ Payload:                                                       │    │
│  │   CRYPTO Frame (ClientHello, ~300 bytes)                       │    │
│  │   PADDING Frame (~850 bytes, 撑到 1200 字节)                    │    │
│  │ Length 字段: 标识本包的 payload+PN+AEAD tag 长度                  │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

这是最简单的情况——只有一个 Initial 包，PADDING 把数据报撑到 1200 字节。

当服务端收到 ClientHello 并回复时，它可能在同一个 UDP 数据报里合并 Initial 和 Handshake 两个包：

```
┌─────────────────────── UDP Datagram (≤ MTU) ────────────────────────────┐
│                                                                         │
│  ┌─── Initial Packet ────────────────────────┐                         │
│  │ Long Header (Version, DCID, SCID)         │                         │
│  │ PN: 0                                     │                         │
│  │ Payload: ACK Frame (确认客户端 Initial #0)  │                         │
│  │ Length: 标识本包边界                        │                         │
│  └───────────────────────────────────────────┘                         │
│                                                                         │
│  ┌─── Handshake Packet ──────────────────────────────────────────┐     │
│  │ Long Header (Version, DCID, SCID)                             │     │
│  │ PN: 0 (Handshake 空间独立编号，从 0 开始)                       │     │
│  │ Payload: CRYPTO Frame (ServerHello + 证书 + ...)               │     │
│  │ Length: 标识本包边界                                            │     │
│  └───────────────────────────────────────────────────────────────┘     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

两个包合并在一个 UDP 数据报里，省去了两次系统调用的开销。接收端通过 Initial 包的 Length 字段找到第一个包的边界，跳到 Handshake 包的起始位置继续解析。如果数据报里还有 1-RTT 包，它一定排在最后——因为短头包没有 Length 字段。

Padding、Token、Coalescing 这三个机制说明了一个道理：Packet 构造不是简单的 Frame 拼装，而是一系列协议约束的协调。容量约束、格式约束、安全约束——每一个"装进包里"的动作，都需要满足协议层面的规则。

---

## 17.5 quicX 的总装配线：PacketBuilder、SendManager 与调度分层如何落地

协议层面的发送管线已经讲清楚了——优先级调度、加密级别约束、Padding/Token/Coalescing。现在看 quicX 是怎么把这些规则落进代码的。

quicX 的发送路径由四个模块协作完成，每个模块只管一件事：

```
                         ┌─────────────────────────────────┐
                         │     BaseConnection::TrySend()   │
                         │         （发送编排入口）            │
                         └──────────────┬──────────────────┘
                                        │
          ┌─────────────────────────────┼─────────────────────────────┐
          ▼                             ▼                             ▼
┌─────────────────┐         ┌────────────────────┐        ┌──────────────────┐
│ EncryptionLevel │         │   SendManager      │        │  RecvControl     │
│ Scheduler       │         │                    │        │                  │
│                 │         │ GetPendingFrames() │        │ MayGenerateAck   │
│ 决定用哪把密钥    │         │ 决定发哪些帧         │        │ Frame()          │
│ GetNextSend     │         │                    │        │ 生成 ACK 帧       │
│ Context()       │         │ wait_frame_list_   │        │                  │
└─────────────────┘         │ stream_manager_    │        └──────────────────┘
                            └────────┬───────────┘
                                     │ 帧列表
                                     ▼
                         ┌────────────────────────┐
                         │    PacketBuilder       │
                         │                        │
                         │ BuildDataPacket()      │
                         │ 把帧装进 Packet，        │
                         │ 设 PN、加密、Padding     │
                         └────────────┬───────────┘
                                      │ 编码后的字节
                                      ▼
                         ┌────────────────────────┐
                         │    UDP Sender          │
                         │    sender_->Send()     │
                         └────────────────────────┘
```

`EncryptionLevelScheduler` 负责回答"用哪把密钥"。它查询当前连接的加密状态，按优先级选择加密级别：跨级别 ACK 最优先，路径探测次之，0-RTT 再次，最后才是当前级别的正常数据。选定级别后，`TrySend()` 拿到对应的 `ICryptographer`。

`SendManager` 负责回答"发哪些帧"。它维护一个待发帧列表 `wait_frame_list_`（`std::list<std::shared_ptr<IFrame>>`）。当连接的各个模块——流管理器、流控、路径管理器——需要发送控制帧时，调用 `ToSendFrame()` 把帧插到列表头部。`GetPendingFrames(level, max_bytes)` 从列表中按序取帧，同时做加密级别过滤：如果当前级别不是 Application，则只取走 ACK、CRYPTO、PADDING、PING、CONNECTION_CLOSE 这五种帧，其余跳过。ACK 帧不在这个列表里——它由 `RecvControl::MayGenerateAckFrame()` 单独生成，然后被 `TrySend()` 插到帧列表的最前面，确保 ACK 总是第一个被编码进包。

`PacketBuilder` 负责"把帧装进包"。它的核心方法是 `BuildDataPacket()`，接收一个 `DataPacketContext`（包含加密级别、密钥、帧列表、流管理器等），输出一个编码好的 Packet。这个方法的工作流程可以概括为六步：

1. 创建 `FixBufferFrameVisitor`，限制 payload 上限为 1420 字节（MTU 1472 减去头部和 AEAD tag 的安全余量）。
2. 逐一把控制帧编码进 visitor 的缓冲区。如果空间不足，停止添加——剩余帧留到下一轮。
3. 如果允许携带流数据，调用 `StreamManager::BuildStreamFrames()` 把流数据帧也编码进来。
4. 如果是 Initial 包且需要 Padding，计算与 1200 字节的差值，补齐 `PaddingFrame`。
5. 根据加密级别创建对应的 Packet 对象（`InitPacket`/`HandshakePacket`/`Rtt1Packet`），设置连接 ID、版本号、Token（仅 Initial）。
6. 从 `PacketNumber` 对象分配新的包号，设置 payload 和 `ICryptographer`，调用 `packet->Encode()` 完成 AEAD 加密和 Header Protection，最后记录到 `SendControl` 用于拥塞控制和丢包追踪。

`BaseConnection::TrySend()` 是整个管线的编排入口。每当有数据就绪（流写入、控制帧入队、定时器触发），连接会调用 `ActiveSend()` 把自己注册到 Worker 的活跃连接列表上。Worker 在事件循环中调度到这条连接时，执行 `TrySend()`。`TrySend()` 做的事情按顺序是：

1. 检查连接状态——已关闭或 Draining 则直接返回。
2. 检查丢包重传——`SendControl` 如果有标记为丢失的包，取出队首，分配新包号，重新 `Encode()` 后直接发送。这条路径优先于新数据，保证丢包恢复的时效性。
3. 获取发送上下文——调用 `EncryptionLevelScheduler::GetNextSendContext()` 确定加密级别和是否有 pending ACK。
4. 检查拥塞窗口——`SendManager::GetAvailableWindow()` 返回当前可用的发送配额。如果为零，标记 cwnd limited 后返回。
5. 获取待发帧——`SendManager::GetPendingFrames()` 过滤出匹配当前加密级别的帧。
6. 生成 ACK 帧——如果有 pending ACK，调用 `RecvControl::MayGenerateAckFrame()` 生成 ACK 帧并插到帧列表最前面。
7. 构建并发送——组装 `DataPacketContext`，调用 `PacketBuilder::BuildDataPacket()`，然后 `SendBuffer()` 交给 UDP 发送。

quicX 还区分了两条发送路径：普通发送（Normal Send）和立即发送（Immediate Send）。上面描述的 `TrySend()` 是普通路径，它经过拥塞控制检查，支持多帧聚合，通过 Worker 事件循环调度。立即发送路径则完全不同——它不经过拥塞控制，不经过 `EncryptionLevelScheduler`，每次只发一个帧。典型的触发场景是：收到对端数据后需要立刻回 ACK（`SendImmediateAck()`），或者路径探测需要立刻发 PATH_RESPONSE。这两条路径的底层都调用 `PacketBuilder`，但触发方式、约束条件、帧容量完全不同。

这种分层的好处是关注点分离。`EncryptionLevelScheduler` 不需要知道帧的内容；`SendManager` 不需要知道密钥是否就绪；`PacketBuilder` 不需要知道帧的优先级。每个模块只做好自己的事，整体协作完成"把语义装进 Packet 发出去"这个任务。当需要修改某条规则——比如调整帧优先级、增加新的加密级别、修改 Padding 策略——改动只会影响一个模块，不会波及整条管线。

---

## 17.6 包从来不是自己长出来的：卷三这一段主线终于闭环

卷三走到这里，QUIC 可靠传输的完整闭环终于合上了。

第 14 章给出了确认坐标——ACK 告诉发送端"哪些包到了"。第 15 章给出了丢包判断——超时和乱序阈值告诉发送端"哪些包可能丢了"。第 16 章给出了语义恢复——丢了的帧不会被原样重发，而是从发送缓冲区里重新取出语义、装进新包。第 17 章给出了实际发送路径——那些等待发送和等待恢复的语义，经过优先级调度、加密级别选择、Padding/Coalescing 约束、`PacketBuilder` 编码，最终变成一个可以交给 UDP 发出去的字节序列。

四章环环相扣：ACK 驱动丢包探测，丢包探测触发语义恢复，语义恢复把帧推进发送管线，发送管线把帧变成 Packet 送上网络——然后新一轮 ACK 开始。

但协议规则从纸面走进代码时，还有一类问题是前面四章都没有触及的：竞态。定时器回调和数据到达交错执行、连接关闭和发送路径并发访问、密钥丢弃和延迟到达的包产生冲突——这些是只有在真正运行的系统里才会暴露的问题。

包从来不是自己长出来的——它是协议设计与工程实现共同孕育的产物。而那些让实现真正"崩掉"的故事，留给下一章。
