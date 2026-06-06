# 11. 连接的生死簿：状态机与传输参数协商

前面几章，我们把 QUIC 从密钥派生到地址验证的建连路径走了一遍。密钥安装了，握手完成了，地址也验证了——但连接真的"活"了吗？答案没有那么简单。TLS Finished 只是加密层的里程碑，不是连接的终点线。双方还要交换一整套传输参数、等服务端盖章发出 HANDSHAKE_DONE，连接才从"正在建立"推进到"可以使用"。而连接的另一头——如何体面地死去、如何在状态丢失时紧急刹车——同样不能留白。**一个 QUIC 连接，从出生到死亡，每一步都被状态机严格约束着。模糊一分，工程里就会多十分混乱。**

---

## 11.1 握完手不等于真的连上：连接建立为什么不是一个瞬间

TLS Finished 收到了，连接就算建立了？

这个答案对了一半。TLS Finished 确实是加密层的里程碑——它意味着双方已经确认了彼此的身份，加密通道已经稳固建立。但 **TLS Finished 并不是连接建立的终点，甚至不是最重要的那个终点**。

QUIC 的连接不只是加密通道。在握手期间，双方还会交换一系列 **transport parameter**（传输参数）——最大流数、流控窗口大小、空闲超时时间、是否支持连接迁移……这些参数直接决定了连接后续的行为方式。**如果双方没有交换完这些参数，即使 TLS 握手已经完成，连接依然处于"在建"状态**——有些能力还不能用，有些行为还受到约束。

更关键的是，QUIC 还需要一个显式的确认信号——**HANDSHAKE_DONE 帧**。服务端在确认双方的 TLS Finished 都交换完毕后才会发出这个帧，它是连接从"正在建立"推进到"已经建立"的最终标志。客户端在收到 HANDSHAKE_DONE 之前，无法确定服务端是否真正确认了握手完成。

这就是为什么"连接建立"不是一个瞬间事件，而是一个**过程**——三个里程碑必须依次到达：TLS Finished 让加密层就绪，transport parameter 交换让传输层就绪，HANDSHAKE_DONE 让服务端盖章确认一切就绪。

在工程实现里，这种"过程性"意味着你不能用一个简单的布尔值 `is_connected` 来判断连接状态。你需要一个真正的**状态机**——每个状态代表连接生命周期中的一个阶段，每个事件（收到某个包、某个验证通过、某个参数交换完成）推动状态向前流动。

这就是 QUIC 状态机存在的意义：**它不是文档附录里的装饰图，而是连接正确性的边界墙**。

---

## 11.2 传输参数不是附表：能力协商为什么必须前置

TCP 也有能力协商——MSS 在 SYN 中交换，Window Scale 和 SACK 通过 TCP Option 协商——但种类有限，且嵌在连接建立的头几个包里就定完了，之后传输层再无"协商"的概念。QUIC 的野心更大：它把传输层的能力协商做成了一套完整的参数体系，和 TLS 握手一起打包发送。

**Transport parameter 到底在约束什么？**

让我们看几个关键的传输参数：

- **max_idle_timeout**：空闲超时时间。如果连接在这个时间内没有任何数据交换，就自动关闭。这个参数必须在建连时达成共识，否则一方以为连接还活着，另一方已经把它超时删除了，就会产生"幽灵连接"。
- **max_stream_data**：单条 Stream 的流控上限。接收方告诉发送方：你最多一次发多少数据到这个 Stream。
- **max_data**：整个连接的总流控上限。接收方告诉发送方：你在这个连接上最多能发多少数据。
- **max_streams**：对端能创建的最大 Stream 数量。
- **active_connection_id_limit**：对端能使用的最大 Connection ID 数量。
- **disable_migration**：是否禁用连接迁移。

这些参数每一个都直接关系到连接的后续行为。**如果双方对这些参数没有达成共识，连接的后续通信就会出问题**。比如客户端想创建 100 条 Stream 发请求，但服务端的 `max_streams` 只允许 10 条——如果不提前协商好，双方对"能发多少"的理解就会产生分歧。

这就是为什么 transport parameter 必须**前置**——它们必须在连接进入稳定状态之前交换完成。**QUIC 把能力协商和密钥交换绑在一起，本质上是在确保：连接一旦"可用"，双方对"怎么用"已经达成共识了**。

具体的传递机制也值得一提。Transport parameter 作为 TLS 扩展 `quic_transport_parameters`（扩展类型 0x39）嵌入握手消息中——客户端的参数放在 ClientHello 里，服务端的参数放在 EncryptedExtensions 里。这意味着客户端的参数在 Initial 阶段就随 ClientHello 出发了（此时 Initial Secret 保护提供的是最低限度的加密），而服务端的参数则在 Handshake 阶段随 EncryptedExtensions 返回，受到 Handshake Secret 的保护。这和 TLS 握手绑在一起并非偶然：transport parameter 是敏感信息——`max_streams` 暴露了服务端愿意为这个连接投入多少资源，`disable_migration` 暴露了服务端的安全策略——这些信息不应该在加密通道之外传输。

从协议的角度看，transport parameter 不是一页"配置清单"，而是一场真正的**能力谈判**。双方都在告诉对方：我能接受什么、我能提供什么、我们的通信边界在哪里。这些边界在握手期定下来，之后的通信就在这些边界内进行。

---

## 11.3 从 connecting 到 connected：状态流转到底在表达什么

连接建立不是一个瞬间，而是"密钥准备好"+"传输参数交换完成"+"HANDSHAKE_DONE 确认"这三个条件共同满足的结果。这一节来看看 QUIC 的状态机是怎么表达这个过程的。

QUIC 连接的生命周期，可以用下面这张状态图来总览：

```
                    OnHandshakeDone()
  ┌────────────┐ ─────────────────────> ┌────────────┐
  │ Connecting │                        │ Connected  │
  └────────────┘                        └────────────┘
        │                                     │
        │ OnClose()                           │ OnClose()
        │ (本端主动关闭)                       │ (本端主动关闭)
        v                                     v
  ┌────────────┐   OnConnectionCloseFrame   ┌────────────┐
  │  Closing   │ ─────────────────────────> │  Draining  │
  │(重发CLOSE) │   Received() (收到对端     │ (静默等待) │
  └────────────┘    CONNECTION_CLOSE)       └────────────┘
        │                                     │
        │ OnCloseTimeout()                    │ OnCloseTimeout()
        v                                     v
                    ┌────────────┐
                    │   Closed   │
                    │  (终态)    │
                    └────────────┘
```

> 注意：Connecting 和 Connected 都可以直接被 `OnConnectionCloseFrameReceived()` 推入 Draining——只要收到对端的 CONNECTION_CLOSE，无论当前处于哪个阶段（除了已经 Closed 或 Draining），都直接进入静默等待。

用两个大阶段来理解建连过程：

**第一个阶段：connecting（连接中）**

这是连接的全部建立过程。客户端发出第一个 Initial 包，服务器收到并开始回复握手消息，双方交换密钥、证书、传输参数——这些全部发生在 connecting 阶段内。这个阶段里，1-RTT 密钥可能已经安装了、客户端可能已经开始发送应用数据了，但连接状态仍然是 connecting——因为握手还没有被双方最终确认。

推动连接离开 connecting 阶段的关键事件是什么？**HANDSHAKE_DONE 帧**。

这里有一个容易被误解的细节：HANDSHAKE_DONE 不是"服务端先于客户端确认握手完成"的单向信号。实际的时序是这样的：

1. 服务端发送 TLS Finished（在 Handshake 包中）
2. 客户端收到后，发送自己的 TLS Finished
3. **服务端收到客户端的 Finished 后**，确认双方的 TLS 握手都已经完成，此时才发送 HANDSHAKE_DONE 帧

也就是说，HANDSHAKE_DONE 是服务端在确认**双方** Finished 都交换完毕之后才发出的盖章确认。它解决的是一个信息不对称问题：客户端发出自己的 Finished 之后，并不知道服务端是否收到了——网络可能丢包。HANDSHAKE_DONE 的作用，就是让客户端确信"服务端确实收到了我的 Finished，握手真的完成了"。

RFC 9000 §19.20 明确规定：**HANDSHAKE_DONE 只由服务端发送**。客户端如果收到了这个帧，就知道握手已经被双方确认，可以安全地丢弃 Initial 和 Handshake 阶段的密钥和包号空间，把资源释放给稳定运行期。

**第二个阶段：connected（已连接）**

这是连接的稳定运行状态。HANDSHAKE_DONE 收到后，transport parameter 已经交换完成，连接进入完全可用状态。双方可以自由创建 Stream、发送数据、不受限制地使用连接的全部能力。

状态机的严谨性体现在这里：**每个状态之间的推进，都必须有明确的事件触发**。不是"差不多连上了"，而是"这个帧收到了、这个验证通过了、这个参数交换完了"，状态才能往前推进。协议里模糊一分，工程里就会多十分混乱——这正是 QUIC 状态机设计的核心原则。

---

## 11.4 一场体面的告别：closing、draining 与连接退出的秩序

连接的退出和建立一样，不是一个瞬间事件，而是一段有秩序的过程。

在 TCP 的世界里，连接关闭是通过 FIN 握手来完成的——双方各发一个 FIN，等对方确认，连接就优雅地关闭了。虽然 TCP 的 TIME_WAIT 状态有时会让人头疼，但总体来说，连接的退出是有章法的。

QUIC 在这方面更复杂，因为它不仅要处理正常的"体面告别"，还要在 UDP 这种无连接的传输层上确保双方对"连接已经结束"达成共识。QUIC 为此设计了两个不同的退出状态，它们的行为差异是理解关闭流程的关键。

**Closing（关闭中）——发起方的状态**

当一方决定关闭连接时（比如服务端要重启、客户端要退出、或者检测到协议错误），它会发送一个 **CONNECTION_CLOSE** 帧，然后进入 closing 状态。CONNECTION_CLOSE 帧携带着错误码（比如 0x0 表示正常关闭，其他错误码表示各种异常），让对方知道为什么连接被关闭了。RFC 9000 定义了两种 CONNECTION_CLOSE 帧：类型 0x1c 用于传输层错误（还会携带触发关闭的帧类型），类型 0x1d 用于应用层关闭（不含帧类型字段）。

RFC 9000 §10.2.1 对 closing 状态有一个关键规定：**在 closing 状态下，端点收到任何属于该连接的包时，都应该重发 CONNECTION_CLOSE 帧**。为什么？因为对方可能没有收到第一次的 CONNECTION_CLOSE，还在那儿继续发数据。每收到一个包就重发一次 CONNECTION_CLOSE，是为了让对方"无论如何都能收到关闭通知"。当然，重发有频率限制——不能因为对方疯狂发包就无限制地回复，quicX 用 PTO（Probe Timeout）来控制重发间隔。

Closing 状态下，端点**不再发送除 CONNECTION_CLOSE 以外的任何数据**——不发 STREAM、不发 ACK、不发 PING，只发关闭通知。

**Draining（排水中）——接收方的状态**

收到 CONNECTION_CLOSE 的一方，进入的是 draining 状态，而不是 closing。Draining 和 closing 的核心区别在于：**draining 状态下，端点不发送任何包**——连 CONNECTION_CLOSE 都不发。

为什么？因为它已经知道对方要关闭了（它收到了 CONNECTION_CLOSE），对方也知道自己发了关闭通知——此时再回复任何东西都是多余的。Draining 状态唯一做的事就是**安静地等待**——等一段时间（通常是 3 × PTO），让在途的数据包自然消亡，然后才删除连接状态。

这个"安静等待"的设计是为了防止一种微妙的错误：如果收到 CONNECTION_CLOSE 后立刻删除连接状态，那些还在网络中飞行的、属于这个连接的包到达后就没有人能处理它们了——更糟的是，如果同一个四元组上很快建了一条新连接，这些"遗留包"可能被错误地当作新连接的数据。等待一个排水期，就是为了让这些在途包在到达后被安全地丢弃。

**两个状态的区别总结**：

- **Closing**：我发了 CONNECTION_CLOSE，但对方可能还没收到 → 所以我还要对收到的包重发 CONNECTION_CLOSE
- **Draining**：我收到了对方的 CONNECTION_CLOSE → 双方已经知情，我安静等待就好

一个生产级的 QUIC 实现，最容易在退出路径上出 bug 的地方是：

- 收到了 CONNECTION_CLOSE 但还在发送数据——应该立刻停止所有发送
- draining 超时时间设置不合理——太短会导致在途包污染新连接，太长会浪费资源
- 正在 closing 时又收到了对方的 CONNECTION_CLOSE——应该从 closing **转为 draining**，因为此时双方已经互相通知，closing 方不再需要重发 CONNECTION_CLOSE。RFC 9000 §10.2.2 明确指出：收到 CONNECTION_CLOSE 的端点进入 draining 状态，无论它之前处于什么状态

还有一个容易被忽略的细节：**closing 和 draining 的超时计算基于 PTO（Probe Timeout）**。RFC 9000 建议等待时间不低于 3 × PTO。PTO 的计算依赖 SRTT 和 RTTVAR——如果连接刚建立、还没有足够的 RTT 样本，quicX 会设置一个最低 500ms 的下限，防止超时时间过短。

这些问题听起来是"工程细节"，但实际上是协议设计的边界问题。**QUIC 把关闭流程做得这么复杂，恰恰是因为它要在无连接的 UDP 之上，重建"有秩序的告别"。**

---

## 11.5 断尾求生：Stateless Reset 为什么不属于正常告别

上一节我们讲了正常的关闭流程——closing + draining + CONNECTION_CLOSE。但 QUIC 还有另一种"死亡方式"，它不属于正常告别，而是**异常兜底**，这就是 **Stateless Reset**（无状态重置）。

什么时候会用到 Stateless Reset？

想象这样一个场景：服务器重启了，内存里的连接状态全丢掉了。但客户端不知道服务器已经"失忆"，还在那儿继续发数据。服务器收到这些数据后，发现自己根本不记得这个连接——没有流、没有密钥、没有流控状态——这堆数据该怎么处理？

服务器有两个选择：

1. **正常关闭**：发一个 CONNECTION_CLOSE，解释一下"对不起我不认识你了"。但问题是，服务器此时已经没有这个连接的状态了，它甚至不知道这个连接最初是怎么建立的。发 CONNECTION_CLOSE 需要一些基本的状态来构建这个帧，如果状态全丢了，可能发不出来。
2. **Stateless Reset**：直接回一个特殊的 Stateless Reset 包，告诉客户端"我不认识这个连接，你从头开始吧"。

Stateless Reset 的设计就是为了解决这种"状态丢失"的极端情况。它不需要任何连接状态——服务器只需要一个预先共享的秘密：**Stateless Reset Token**。这个 16 字节的令牌在建连时通过 transport parameter 的 `stateless_reset_token` 字段交给客户端（后续的新 Connection ID 也通过 NEW_CONNECTION_ID 帧携带各自的 Token）。服务器重启后，只要能用同一个密钥从 Connection ID 重新派生出这个 Token，就能构造一个合法的 Stateless Reset 包——客户端验证包尾部的 Token 匹配后，就知道对方确实是"那个曾经认识我的服务器"。

**但 Stateless Reset 不是正常关闭流程的一部分**。它们有几个关键区别：

- **CONNECTION_CLOSE** 是"我们商量好了一起关掉连接"，是双向共识
- **Stateless Reset** 是"我不认识这个连接了，你看着办吧"，是单方面"失忆"

从语义上说，Stateless Reset 更像是一种"异常兜底"——当正常流程走不通时的一种紧急刹车。它告诉客户端：连接状态已经丢失了，你不需要等待 closing/draining 的流程，直接重新建连吧。

对于实现者来说，理解这两种"死亡方式"的区别非常重要：

- **正常关闭**（closing/draining/CONNECTION_CLOSE）是有秩序的告别，双方有共识，资源会逐步释放
- **Stateless Reset** 是紧急刹车，是"我不认识你了"的单方面宣言，客户端收到后应该立刻尝试重新建连，而不是试图恢复旧连接

一个健壮的 QUIC 实现必须同时处理好这两条路径——既要有优雅关闭的能力，也要有异常兜底的准备。

---

## 11.6 quicX 的生命曲线：状态机、参数安装与关闭路径如何落地

理解了协议层面的状态机和关闭语义，我们来看 quicX 是怎么把它们落进代码的。连接生命周期管理涉及三个核心模块的协作：**ConnectionStateMachine**（状态机）、**TransportParam**（传输参数）和 **ConnectionCloser**（关闭管理器）。它们被 `BaseConnection` 持有，彼此解耦又通过事件和回调紧密联动。

**第一，ConnectionStateMachine——五个状态，四条转换路径。**

quicX 的连接状态机把协议规定的生命周期压缩成五个枚举值：

```cpp
enum class ConnectionStateType {
    kStateConnecting,   // 握手进行中
    kStateConnected,    // 稳定运行
    kStateClosing,      // 已发 CONNECTION_CLOSE，等待 1×PTO
    kStateDraining,     // 收到对端 CONNECTION_CLOSE，静默等待 3×PTO
    kStateClosed,       // 终态，资源可回收
};
```

状态之间的推进不是靠条件判断的模糊逻辑，而是四个明确的事件方法：

```cpp
void ConnectionStateMachine::OnHandshakeDone() {
    if (state_ == ConnectionStateType::kStateConnecting) {
        SetState(ConnectionStateType::kStateConnected);      // ← 唯一的建连完成路径
    }
}

void ConnectionStateMachine::OnClose() {
    if (state_ == ConnectionStateType::kStateConnected ||
        state_ == ConnectionStateType::kStateConnecting) {
        SetState(ConnectionStateType::kStateClosing);         // ← 本端主动关闭
    }
}

void ConnectionStateMachine::OnConnectionCloseFrameReceived() {
    if (state_ != ConnectionStateType::kStateClosed &&
        state_ != ConnectionStateType::kStateDraining) {
        SetState(ConnectionStateType::kStateDraining);        // ← 收到对端关闭
    }
}

void ConnectionStateMachine::OnCloseTimeout() {
    if (state_ == ConnectionStateType::kStateClosing ||
        state_ == ConnectionStateType::kStateDraining) {
        SetState(ConnectionStateType::kStateClosed);          // ← 超时后终态
    }
}
```

注意 `OnConnectionCloseFrameReceived()` 的守卫条件——它排除了 Closed 和 Draining，但**没有排除 Closing**。这意味着：正在 closing 的端点收到了对方的 CONNECTION_CLOSE，会从 closing 转入 draining。这正是 11.4 节提到的"双方互相通知后不再需要重发"的精确落地。

状态机还通过 `IConnectionStateListener` 接口把每次状态变更通知给 `BaseConnection`。`SetState()` 内部的 switch-case 会调用 `listener_->OnStateToClosing()` / `OnStateToDraining()` / `OnStateToClosed()` 等回调，`BaseConnection` 在这些回调里执行真正的清理动作——清空重传队列、构造 CONNECTION_CLOSE 帧、设置超时定时器。状态机只管"什么时候该做什么"，不管"具体怎么做"。

状态机还提供了一组查询方法来约束连接行为的边界：

```cpp
bool AllowSend() const;          // Connecting || Connected 才允许发包
bool CanSendData() const;        // 仅 Connected 才允许发应用数据
bool CanReceiveData() const;     // Connected || Closing 才处理数据
bool ShouldIgnorePackets() const; // Draining || Closed 直接丢弃
bool IsTerminating() const;      // Closing || Draining || Closed
```

`AllowSend()` 和 `CanSendData()` 的区别值得注意：Connecting 阶段允许发送握手包（`AllowSend() == true`），但不允许发送应用数据（`CanSendData() == false`）。这两个方法的分离，就是"握手完成≠连接建立"在代码层面的体现。

**第二，TransportParam——协商的落地是一次 Merge。**

quicX 没有单独的"传输参数管理器"类——`TransportParam` 自己就承担了编解码、协商合并和通知的全部职责。它的字段直接对应 RFC 9000 §18 定义的传输参数：

```cpp
class TransportParam {
    std::string original_destination_connection_id_;
    uint32_t max_idle_timeout_;
    std::string stateless_reset_token_;  // 仅服务端
    uint32_t initial_max_data_;
    uint32_t initial_max_stream_data_bidi_local_;
    uint32_t initial_max_stream_data_bidi_remote_;
    uint32_t initial_max_streams_bidi_;
    uint32_t initial_max_streams_uni_;
    bool disable_active_migration_;
    uint32_t active_connection_id_limit_;
    // ... 省略其余字段
};
```

连接建立时，`Init()` 从本地配置加载参数，然后触发所有监听器。当对端的传输参数在 TLS 握手中到达后，`Merge()` 把双方的参数合并成最终生效值——关键在于合并策略：

```cpp
bool TransportParam::Merge(const TransportParam& tp) {
    max_idle_timeout_ = std::min(tp.max_idle_timeout_, max_idle_timeout_);
    initial_max_data_ = std::min(tp.initial_max_data_, initial_max_data_);
    initial_max_streams_bidi_ = std::min(tp.initial_max_streams_bidi_, initial_max_streams_bidi_);
    // ... 数值型参数一律取 std::min（取较保守的一方）
    disable_active_migration_ = disable_active_migration_ || tp.disable_active_migration_;
    // ↑ 布尔型用逻辑 OR：任何一方禁用迁移，连接就不能迁移
    for (auto& listener : transport_param_listeners_) {
        listener(*this);  // 合并完成后立即通知所有监听器
    }
    return true;
}
```

`std::min` 策略的含义是：**能力协商永远向保守方看齐**。如果客户端说"我能接受 100 条流"，服务端说"我只给你 10 条"，最终结果就是 10 条。这和 TLS 的密码套件协商不同——TLS 协商的是"挑一个双方都支持的"，而 transport parameter 协商的是"取一个双方都能承受的"。

`Merge()` 结束后触发的监听器回调，会把新参数推送到流控制器、流管理器等下游模块——`max_stream_data` 安装后，发送端立刻就知道"这个 Stream 最多能发多少数据了"。这个推送是同步的，不存在"参数已合并但下游还不知道"的窗口期。

Transport parameter 的编解码使用 QUIC 的变长整数（varint）格式，按 type-length-value 三元组排列。每个参数先写 type（如 `kMaxIdleTimeout = 0x01`），再写 length，最后写 value。这和 TLS 扩展的编码方式一致——毕竟它就是作为 TLS 扩展 `quic_transport_parameters`（0x39）嵌入握手消息的。

**第三，ConnectionCloser——两条关闭路径的交通管制员。**

`ConnectionCloser` 是关闭逻辑的集中管理点。它持有状态机和发送管理器的引用，但不拥有它们——职责边界清晰：

```cpp
class ConnectionCloser {
    // 依赖注入
    ConnectionStateMachine& state_machine_;
    SendManager& send_manager_;
    TransportParam& transport_param_;
    ConnectionCloseCallback connection_close_cb_;

    // 关闭信息（用于 CONNECTION_CLOSE 重传）
    uint64_t closing_error_code_{0};
    uint16_t closing_trigger_frame_{0};
    std::string closing_reason_;
    uint64_t last_connection_close_retransmit_time_{0};

    // 优雅关闭状态
    bool graceful_closing_pending_{false};
    TimerTask graceful_close_timer_;

    // 回调去重
    bool connection_close_cb_invoked_{false};
};
```

`ConnectionCloser` 同时管理两条路径。**优雅关闭**时，`StartGracefulClose()` 会先检查是否有待发数据：

```cpp
bool ConnectionCloser::StartGracefulClose(ActiveSendCallback active_send_cb) {
    if (send_manager_.GetSendOperation() != SendOperation::kAllSendDone) {
        // 还有数据没发完，先等
        graceful_closing_pending_ = true;
        graceful_close_timer_ = TimerTask(
            std::bind(&ConnectionCloser::OnGracefulCloseTimeout, this));
        event_loop_->AddTimer(graceful_close_timer_, GetCloseWaitTime() * 3, 0);
        return true;  // ← 进入等待，不立即转状态
    }
    // 没有待发数据，直接进入 Closing
    closing_error_code_ = QuicErrorCode::kNoError;
    state_machine_.OnClose();  // ← 触发状态机转换
    return true;
}
```

这里有一个工程上的权衡：优雅关闭不是无限等待。`GetCloseWaitTime() * 3` 设置了一个超时（大约 3 倍 PTO 再乘以 3），超时后 `OnGracefulCloseTimeout()` 会强制进入 Closing——不能因为数据发不完就永远不关闭连接。

**立即关闭**则更简单——`StartImmediateClose()` 先取消优雅关闭（如果有的话），然后直接触发状态机转换：

```cpp
void ConnectionCloser::StartImmediateClose(uint64_t error, uint16_t trigger_frame,
    const std::string& reason, ActiveSendCallback active_send_cb) {
    CancelGracefulClose();  // ← 如果优雅关闭在等待，立刻取消
    closing_error_code_ = error;
    closing_trigger_frame_ = trigger_frame;
    closing_reason_ = reason;
    state_machine_.OnClose();  // ← 直接转 Closing
}
```

进入 Closing 后，每收到一个包都要判断是否需要重发 CONNECTION_CLOSE。`ShouldRetransmitConnectionClose()` 用 PTO 做节流——每个 PTO 周期最多重发一次，避免被对方的发包洪水淹没。

Closing/Draining 超时后，状态机推入 `kStateClosed`，`BaseConnection::OnStateToClosed()` 回调应用层——连接彻底死亡，资源可以回收了。

**三个模块的协作关系**：

```
BaseConnection（实现 IConnectionStateListener 接口）
  ├── ConnectionStateMachine    → "什么时候该做什么"
  ├── TransportParam            → "当前能做什么"
  ├── ConnectionCloser          → "什么时候不能做了、该怎么停"
  ├── FrameProcessor            → 帧分发（CONNECTION_CLOSE / HANDSHAKE_DONE 回调入口）
  ├── SendManager               → 发送控制
  └── TimerCoordinator          → 定时器协调（空闲超时 + PTO 检查）
```

`ConnectionStateMachine` 通过 Observer 模式通知 `BaseConnection` 状态变更，`BaseConnection` 在回调中协调各组件完成实际的清理操作。`ConnectionCloser` 封装了关闭路径的所有状态和定时器逻辑，让 `BaseConnection` 的关闭代码不至于变成一团 if-else 泥潭。`TransportParam` 的监听器机制则让参数变更自动扩散到流控制器和流管理器，不需要手动同步。

这三个模块各司其职，但严格遵守一个原则：**状态推进是唯一的真相来源**。任何行为变更（能不能发数据、该不该处理包、要不要重发 CONNECTION_CLOSE）都先查状态机，再做决定。没有任何模块能绕过状态机直接改变连接的行为——这就是"状态机是边界墙"在工程里的落地方式。

---

## 11.7 活着，比连上更难

状态机不是装饰，而是连接正确性的边界墙。

它把含混的人类判断——"差不多已经连上了"、"应该可以发数据了吧"——变成严格的协议边界：必须收到 HANDSHAKE_DONE 才能进入 Connected，必须等 draining 结束才能删除状态，正在 closing 时收到对端的 CONNECTION_CLOSE 就转入 draining 不再重发。每一条边界都是某个曾经出过的 bug 凝固成的规则。

Transport parameter 把能力协商从"隐式假设"变成"显式契约"——双方不用猜对方能做什么，所有边界在握手期就白纸黑字地定好了。而关闭路径的两张面孔——优雅退出的 closing/draining 和异常兜底的 Stateless Reset——确保连接无论以何种方式死去，都不会留下能污染后续连接的残骸。

真正难的，不是让连接开始，而是让它始终处在正确状态。**连接的生命周期管理，本质上是一场对模糊性的持续消灭。**

既然连接已经稳定存在了，下一个问题自然浮现：一个已经"活着"的连接，能否脱离原来的 IP 四元组继续活下去？这就是 Connection ID 与连接迁移的领地。
