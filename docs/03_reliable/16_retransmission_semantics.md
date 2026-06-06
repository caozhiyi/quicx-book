# 16. 重传的边界：重发的不是 Packet，而是语义

上一章回答了"什么时候算丢"——时间阈值、包阈值、PTO 三条线交叉验证，给出一个概率推断。但判丢只是起点。真正的问题紧随其后：既然一个包被判定失踪了，该重发的到底是包本身，还是包里承载的语义？

这个问题的答案，决定了 QUIC 重传机制与 TCP 的根本差异。TCP 可以把丢失的字节区间原样补发，因为它的可靠性单位就是字节位置。QUIC 不行——它的传输单元是 Packet，但 Packet 只是一次投递尝试，里面承载的 Frame 才是连接真正想表达的意图。丢了一个 Packet，QUIC 恢复的不是那个 Packet 的物理副本，而是那些未送达的协议语义。

本章从 TCP 的字节流旧法则讲起，推导出 QUIC 为什么必须走语义重传这条路，再拆解不同帧类型在丢失后的不同恢复命运，最后落到 quicX 的具体实现路径。

---

## 16.1 字节流的旧法则：TCP 为什么可以直接重发那一段

要理解 QUIC 的做法，先回到 TCP 的旧世界看看。

TCP 的重传逻辑建立在一个简单的事实上：TCP 传输的是字节流。数据从一端流进去，从另一端流出来。发送端写入了 1000 字节，接收端按顺序收到这 1000 字节。每一个字节都有一个位置——序列号（Sequence Number）标记它在流中的绝对偏移。

当某个字节丢失时，TCP 的处理方式非常直接：重新发送丢失的那个字节区间。比如发送了字节 1000-2000，中途丢了 1000-1500，TCP 重新发送这 500 个字节。接收端收到后，把它放到正确的位置——它知道这 500 个字节应该填补在"1000"这个偏移后面。重传包使用相同的序列号范围，和原始包在语义上完全等价。

```
TCP 字节流重传：

发送端缓冲区：  [====== 字节 0~2000 ======]
                 ↓
原始发送：      SEQ=1000, LEN=500 ───→ ✗ 丢失
                 ↓
重传：          SEQ=1000, LEN=500 ───→ ✓ 到达
                 (相同序列号，相同数据)

接收端：把字节填入 offset 1000 的位置 → 完成
```

这种方式的优点是简单直观。发送端只需要记住"我发送到了哪个字节位置"，接收端只需要记住"我接收到了哪个字节位置"。重传时双方都知道该补什么——序列号就是身份证，同一个序列号永远对应同一段数据。

但这种简单是有代价的。TCP 的可靠性和"字节流"这个传输模型绑定在一起。如果换一种传输模型——比如不再是一根水管，而是多根水管同时流——TCP 的重传逻辑就会出问题。Stream A 丢了一个包，Stream B、C 的数据也被卡住，因为 TCP 只有一条字节流，序列号是全局递增的。这就是 HTTP/2 在 TCP 之上遭遇队头阻塞的根源。

QUIC 不走这条路。它选择了另一条更灵活、代价也更高的道路。

---

## 16.2 包已经死了，语义还活着：QUIC 为什么拒绝"整包复刻"

QUIC 重传的不是 Packet，而是 Packet 里面承载的语义——这是 QUIC 和 TCP 最本质的区别之一。要理解这一点，需要从 QUIC 的协议结构特征出发做推导。

第一个结构约束：Packet Number 单调递增，不复用。RFC 9000 §17.1 规定，每个 Packet Number 在同一个 Packet Number Space 内只使用一次。这意味着重传一个包时，不可能使用原来的 Packet Number——它必须获得一个新的编号。既然编号都变了，这个包在协议层面就是一个全新的包，不是原始包的"副本"。

第二个结构约束：多加密级别共存。QUIC 连接在不同阶段使用不同的加密密钥（Initial、Handshake、1-RTT）。一个在 Handshake 阶段丢失的包，在 1-RTT 密钥可用后重传时，可能需要换用新的加密级别。同一个语义内容（比如一个 CRYPTO Frame），前后两次发送可能用完全不同的密钥加密——包的物理形态已经不同了。

第三个结构约束：帧独立编码，包只是容器。一个 QUIC Packet 可以携带多个不同类型的 Frame——STREAM、ACK、MAX_DATA、PING 可能共存于同一个包里。当这个包丢失时，并非所有帧都需要重传：ACK 帧不需要重传（RFC 9000 §13.3 明确列出），PADDING 帧不需要重传，而 STREAM 帧和控制帧则需要。恢复的单位是帧，不是包。

这三个约束叠加在一起，让"把原来的包再发一遍"在协议层面既不可能也不合理。QUIC 的做法是：重新构造包含相同语义的新包。如果丢失的包里有一个 STREAM Frame 承载了 offset 200-400 的数据，重传时 QUIC 从 Stream 的发送记录里取出相同偏移范围的数据，装进一个新 Packet Number 的包里发出去。从接收端的角度看，它收到的不是"同一个包的副本"，而是"同一个语义的新表达"。

```
QUIC 语义重传：

原始发送：  PN=5  [STREAM(sid=1, off=200, len=200) + MAX_DATA(limit=8000)]
                   ↓
            PN=5 ───→ ✗ 丢失
                   ↓
重传：      PN=12 [STREAM(sid=1, off=200, len=200) + MAX_DATA(limit=9500)]
                   (新 PN，STREAM 数据相同，MAX_DATA 已更新为最新值)

接收端：按 stream_id + offset 匹配 → 填入正确位置 → 完成
```

上图揭示了一个关键细节：重传包里的 MAX_DATA 不是原始值 8000，而是当前最新值 9500。因为 MAX_DATA 的语义是"告诉对端我当前的接收窗口上限"，重传时发送最新值比复制旧值更合理——RFC 9000 §13.3 对此有明确要求："the most recent value is sent"。这正是"语义重传"而非"字节复制"的体现。

---

## 16.3 同样是丢失，恢复的命运却不同：控制帧、流帧与握手帧的差异

QUIC 的语义重传不是"一视同仁"的。不同类型的 Frame，在丢失后的恢复方式截然不同。RFC 9000 §13.3 对此做了系统性的分类。

首先是不需要重传的帧。ACK 帧、PADDING 帧不携带需要可靠传输的语义，丢失后直接丢弃即可。PATH_CHALLENGE 和 PATH_RESPONSE 也不重传——它们用于路径验证，丢失后由上层逻辑决定是否发起新的验证。CONNECTION_CLOSE 帧虽然重要，但它的重传由专门的 closing 状态机处理，不走常规重传路径。

然后是"最新值覆盖型"控制帧。MAX_DATA、MAX_STREAM_DATA、MAX_STREAMS 这类帧携带的是一个单调递增的限制值。如果丢失了一个 MAX_DATA(limit=8000)，但此后接收端的窗口已经扩大到 9500，重传时应当发送 MAX_DATA(limit=9500)，而不是过时的 8000。RFC 9000 §13.3 明确说："new frames are sent with updated information"。这些帧不是简单的幂等重发——它们需要用当前最新状态替换历史值。

还有"真正幂等型"控制帧。PING 帧没有参数，发多次和发一次效果一样。NEW_CONNECTION_ID、RETIRE_CONNECTION_ID 等帧携带固定的语义内容，重传时原样发送即可。HANDSHAKE_DONE 也是如此——它只是一个信号，告诉对端握手已完成。

握手帧（CRYPTO Frame）是一个特殊类别。CRYPTO Frame 承载 TLS 握手数据，使用独立于 Stream 的偏移空间。如果一个 CRYPTO Frame 丢失，重传时从加密层的发送缓冲区取出相同偏移位置的握手数据，装进新包发送。握手数据的特殊性在于它们绑定特定的加密级别——Initial 阶段的 CRYPTO Frame 不能在 1-RTT 阶段重传，因为对端可能已经丢弃了 Initial 密钥。

流帧（STREAM Frame）是最复杂的。STREAM Frame 携带应用数据，数据在 Stream 内部通过 offset 定位。一个 STREAM Frame 丢失后，重传的不是"原来的 Frame 对象"，而是 Stream 发送缓冲区中对应偏移范围的数据。

用一个具体例子来说明：

```
Stream #1 发送缓冲区内容（5 个帧，每帧 200 字节）：

  PN=3: STREAM(off=0,   len=200) ──→ ✓ ACKed
  PN=4: STREAM(off=200, len=200) ──→ ✗ 丢失
  PN=5: STREAM(off=400, len=200) ──→ ✓ ACKed
  PN=6: STREAM(off=600, len=200) ──→ ✓ ACKed
  PN=7: STREAM(off=800, len=200) ──→ 在途

收到 ACK{largest=6, ranges=[3,3],[5,6]} 后：
  → PN=4 后面有 3 个包被确认（6-4≥3）→ 判丢
  → 重传：PN=9: STREAM(off=200, len=200)  ← 同一 offset，新 PN
  → 接收端按 stream_id=1, offset=200 填入正确位置
```

下表汇总了 RFC 9000 §13.3 中各类帧在丢失后的恢复策略：

| 帧类型 | 恢复策略 | 说明 |
|--------|---------|------|
| ACK, PADDING | 不重传 | 无需可靠传输 |
| PATH_CHALLENGE, PATH_RESPONSE | 不重传 | 路径验证由上层重新发起 |
| CONNECTION_CLOSE | closing 状态机处理 | 不走常规重传路径 |
| MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS | 发送最新值 | 单调递增，旧值无意义 |
| DATA_BLOCKED, STREAM_DATA_BLOCKED | 发送最新值 | 阻塞点可能已变化 |
| PING, HANDSHAKE_DONE | 原样重发 | 真正幂等 |
| NEW_CONNECTION_ID, RETIRE_CONNECTION_ID | 原样重发 | 固定语义内容 |
| CRYPTO | 从加密缓冲区按偏移重发 | 绑定特定加密级别 |
| STREAM | 从 Stream 发送缓冲区按偏移重发 | 最复杂的恢复路径 |

这种分类的意义在于：不同类型的语义有不同的生命周期和重传约束。控制帧可能需要更新值，握手帧绑定加密级别，流帧按偏移定位。QUIC 的语义重传设计，让每种 Frame 都能找到最适合自己的恢复路径。

---

## 16.4 重发的自由，也是实现的负担：这种设计到底换来了什么，又付出了什么

QUIC 的语义重传设计，是一场带成本的结构交换。先看收益，再看代价。

多路复用不再被可靠性绑架。在 TCP 里，Stream A 的数据丢了，整个连接的字节流都要停下来等重传——因为 TCP 只有一条序列号空间。在 QUIC 里，Stream A 丢了一个包，Stream B、C 完全不受影响。每个 Stream 的语义独立维护，重传独立进行。这直接消除了 TCP 层面的队头阻塞。

重传包使用新的 Packet Number，带来了额外的收益。这里有一个 TCP 长期头疼的问题：重传歧义（retransmission ambiguity）。考虑以下场景：

```
TCP 重传歧义：

  t=0ms    发送 SEQ=1000
  t=100ms  超时，重传 SEQ=1000（相同序列号）
  t=150ms  收到 ACK(SEQ=1000)

  问题：这个 ACK 确认的是 t=0 的原始包（RTT=150ms）
        还是 t=100 的重传包（RTT=50ms）？
        → 无法区分，RTT 测量失效
```

TCP 通过 Karn 算法绕过：放弃用重传包的 ACK 更新 RTT。代价是在丢包频繁时 RTT 估算长时间得不到更新，PTO/RTO 的计算会偏离实际网络状态。

QUIC 不存在这个问题。重传包使用全新 PN，接收端 ACK 这个新 PN 时，发送端能精确计算这次重传的 RTT——PN 唯一标识一次发送行为，ACK 唯一对应一个 PN，没有歧义。

下表对比了两种重传机制的核心差异：

| 维度 | TCP 字节流重传 | QUIC 语义重传 |
|------|---------------|--------------|
| 恢复单位 | 字节区间（相同 SEQ） | 帧语义（新 PN） |
| 多路复用影响 | 全连接阻塞 | 仅受损 Stream 重传 |
| 重传歧义 | 存在（Karn 算法规避） | 不存在（PN 唯一） |
| RTT 测量 | 重传包不可用于测量 | 重传包可正常测量 |
| 控制信息 | 随字节流一起重传 | 可更新为最新值 |
| 实现复杂度 | 低（维护字节偏移即可） | 高（帧级别追踪） |

但这种设计也带来了实现复杂度的显著上升。

发送端需要维护大量状态。每个 Packet 需要记录它携带了哪些帧、哪些 Stream 的哪些 offset 范围——这样在收到 ACK 时才能精确推进每个 Stream 的确认进度。quicX 中 `PacketTimerInfo` 结构体就承担了这个角色，它保存了每个未确认包的发送时间、包大小、携带的 Stream 数据信息（`StreamDataInfo`）以及完整的包对象。

接收端需要做语义重组。收到重传的 STREAM Frame 后，接收端需要按 stream_id 和 offset 把它放到正确的 Stream 位置，可能需要和已经收到的其他 Frame 合并、排序。这比 TCP 的"收到字节就放入缓冲区"要复杂得多。

拥塞控制需要协调。重传的 Packet 和新 Packet 一样——它们占用拥塞窗口，参与拥塞控制计算。如果拥塞窗口不足，重传包也要排队等待（quicX 中 `TrySend()` 会检查 `GetAvailableWindow()`，窗口不足时将丢失包放回队列）。

---

## 16.5 quicX 的恢复路径：发送记录、语义重组与再次投递如何落地

协议层面讲清楚之后，来看 quicX 如何在代码里组织这套系统。重传涉及三个核心阶段：丢包后的包记录保留、重传触发链路、以及语义的再次投递。

**第一阶段：发送时的状态记录。** 每个包发送时，`SendControl::OnPacketSend()` 会创建一个 `PacketTimerInfo` 条目，保存发送时间、包大小、关联的 Stream 数据信息（哪些 Stream 的哪些 offset 范围），以及完整的 `IPacket` 对象引用。这些条目按 Packet Number Space 组织在 `unacked_packets_[ns]` 哈希表中，等待后续的 ACK 确认或丢包判定。同时为每个包注册一个 PTO 定时器，超时则触发丢包处理。

**第二阶段：丢包判定与重传触发。** 当 ACK 到达时，`SendControl::OnPacketAck()` 处理完确认逻辑后调用 `DetectLostPackets()`。该方法遍历对应 Packet Number Space 中所有未确认的包，用包阈值（`kPacketThreshold = 3`）和时间阈值（`9/8 × smoothed_rtt`）交叉检查。被判丢的包经历以下处理：

```
DetectLostPackets() 判定 PN=4 丢失：
  → 取消 PN=4 的 PTO 定时器
  → 将 IPacket 对象加入 lost_packets_ 队列
  → 通知拥塞控制模块 OnPacketLost()
  → 触发 packet_lost_cb_ 回调
  → 从 unacked_packets_[ns] 中移除
```

`packet_lost_cb_` 在 `SendManager` 构造时注册，它的作用是调用 `send_retry_cb_()`——这个回调绑定到 `BaseConnection::ActiveSend()`，将连接加入 Worker 的活跃发送队列，触发 `TrySend()` 的下一轮执行。

**第三阶段：语义的再次投递。** `BaseConnection::TrySend()` 是重传的执行入口。它优先检查 `lost_packets_` 队列——如果有丢失包等待重传，从队列头部取出 `IPacket` 对象，执行以下操作：

```
TrySend() 重传路径：
  → 检查拥塞窗口（窗口不足则放回队列，标记 cwnd 受限）
  → 分配新 Packet Number：new_pn = PacketNumber::NextPacketNumber(ns)
  → 设置新加密器：lost_pkt->SetCryptographer(cryptographer)
  → 重新编码：lost_pkt->Encode(buffer)
  → 在 SendControl 中重新注册追踪（以便追踪这次重传的 ACK/丢失）
  → 发送到网络
```

quicX 的实现策略值得注意：它保留了丢失包的完整 `IPacket` 对象（包括其中的帧和 payload），重传时只替换 Packet Number 和加密器，然后重新编码发送。这和"逐帧拆解再重新组包"的方案不同——quicX 选择了更简洁的整包重编码路径。

这个设计选择有明确的取舍。RFC 9000 §13.3 描述的是帧级别的语义恢复——理论上最灵活的做法是：拆出丢失包中的每个帧，过滤掉不需要重传的（ACK、PADDING），将需要重传的帧重新组合到新包中，并更新 MAX_DATA 等控制帧为最新值。quicX 的整包重编码方案牺牲了这种灵活性（比如不会在重传时更新 MAX_DATA 为最新值），换来了实现的简洁和更低的 CPU 开销——不需要拆帧、过滤、重组，只需换号、换密钥、重编码。对于一个追求清晰可审计的实现来说，这是合理的取舍。

**ACK 确认如何推进 Stream 状态。** 当重传包的 ACK 到达时，`SendControl::OnPacketAck()` 遍历该包关联的所有 `StreamDataInfo`，对每个 Stream 调用 `stream_data_ack_cb_`。这个回调链最终到达 `SendStream::OnDataAcked()`，将 `acked_offset_` 推进到已确认的最大偏移量。当所有数据（包括 FIN）都被确认后，`CheckAllDataAcked()` 将 Stream 状态机推入终态。

下面这张流程图概括了 quicX 中从丢包判定到语义恢复的完整链路：

```
                    收到 ACK
                       │
                       ▼
          SendControl::OnPacketAck()
            ├── 更新 RTT
            ├── 推进 Stream acked_offset
            └── DetectLostPackets()
                       │
                 判定 PN=4 丢失
                       │
                       ▼
              lost_packets_.push(pkt)
              packet_lost_cb_()
                       │
                       ▼
           SendManager → send_retry_cb_()
                       │
                       ▼
         BaseConnection::ActiveSend()
                       │
                       ▼
         BaseConnection::TrySend()
            ├── 从 lost_packets_ 取出包
            ├── 分配新 PN=12
            ├── 设置新加密器
            ├── Encode() 重新编码
            ├── OnPacketSend() 重新注册追踪
            └── 发送到网络
```

---

## 16.6 真正被重发的，是连接想说的话

回到本章开头的问题：如果包真的丢了，QUIC 怎么把它"捞"回来？

答案是：QUIC 恢复的不是那个 Packet 的物理副本，而是 Packet 里承载的协议语义。是 Stream 里特定偏移位置的应用数据，是握手过程中需要重传的 CRYPTO 消息，是需要更新为最新值的 MAX_DATA 窗口通告，是不需要重传的 ACK 和 PADDING。每种语义有自己的生命周期和恢复约束，不可能用一个统一的"再发一遍"来处理。

这种设计让多路复用摆脱了可靠性的绑架，让重传包的 RTT 测量不再有歧义，让控制信息能携带最新状态而非过时副本。代价是发送端必须为每个包维护帧级别的发送记录，为每个 Stream 追踪确认偏移——quicX 中 `PacketTimerInfo`、`StreamDataInfo`、`SendStream::acked_offset_` 这些结构正是为此而存在。

Packet 只是一次说话机会，语义才是连接真正想表达的内容。判丢是上半篇，语义恢复是下半篇——接下来要回答的是：这些需要恢复的语义，最终怎样被重新组织进新的 Packet 里发出去？这就是第 17 章要进入的话题。
