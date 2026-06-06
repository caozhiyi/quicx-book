# 14. ACK 的艺术：序列号空间与确认边界

第 13 章把 QUIC 可靠性的骨架搭好了——三层各管一层，确认不拖交付，交付不拖恢复。但骨架只是骨架，真正让确认层运转起来的，是两个具体问题：编号怎么管？确认怎么说？

TCP 用了四十年的方式是：一个连接一套序号，一个累计确认点，不够用再加 SACK 选项。这个方案在 TCP 的世界里足够了——一条连接只有一种加密状态、一种确认节奏。但 QUIC 不一样。QUIC 的连接同时容纳着多种加密级别、多种确认策略、多种生命周期。如果继续沿用 TCP 的单一编号空间，这些差异会在确认逻辑里互相踩踏，制造出一系列难以调和的工程矛盾。

QUIC 给出的方案是双管齐下：用 Packet Number Space 把编号世界隔离开，用 ACK Frame 把确认语言做到极致精确。这两个机制一个管边界、一个管表达，共同构成了确认层的完整能力。

这一章从编号的隔离问题切入，然后看三个空间的生命周期，再拆解 ACK Frame 的确认语言和信号维度，最后落到 quicX 的实现里看这套确认账本的工程形态。

---

## 14.1 编号为什么不能混在一起

QUIC 的一个连接里同时跑着三类性质完全不同的流量：Initial 阶段的握手引导、Handshake 阶段的密钥交换、Application 阶段的业务数据。如果像 TCP 那样只维护一套编号——Initial 包编 1、2、3，Handshake 包编 4、5，Application 包编 6、7、8——接收端只看编号，根本无法区分它们属于哪个阶段、该用哪把密钥解密。

但编号混用带来的问题远不止"分不清谁是谁"。两个更深层的结构性矛盾，注定了混用编号在工程上行不通。

**第一个矛盾：密钥的生命周期不一样。**

Initial 密钥是用连接 ID 派生的"公开秘密"，它只在握手启动阶段有意义。一旦 Handshake 密钥可用，Initial 密钥就应当被丢弃——继续持有它没有安全意义，还会浪费状态空间。RFC 9000 §4.10 明确规定了这一点：当更高加密级别的密钥安装完毕，旧密钥及其对应的所有确认状态都应被丢弃。

如果所有阶段混用同一套编号，"丢弃旧密钥"这件事就变得危险了：编号 3 属于 Initial 阶段，你把 Initial 的确认状态清掉了，但编号 3 还在全局的 unacked 列表里——判丢逻辑该怎么处理它？重传逻辑该用什么密钥重发它？发送端无法区分"属于已废弃密钥空间的未确认包"和"真正需要重传的包"。唯一干净的解法是：让不同密钥阶段各自拥有独立的编号空间和独立的确认状态，废弃密钥时把整个空间一起清掉，不影响其他空间。

**第二个矛盾：确认策略不一样。**

握手阶段的 Initial 和 Handshake 包必须**立即确认**——RFC 9000 §13.2.1 明确要求这一点，因为握手推进不能有延迟。但 Application 阶段的包可以**延迟确认**——接收端可以累积若干包后再发一个 ACK，这样能减少 ACK 帧的数量、降低开销。

如果混用编号，同一个确认空间内的 RTT 采样就会被两种完全不同的确认策略污染。一个 Initial 包被立即 ACK，RTT 采样很干净；紧接着一个 Application 包被延迟 ACK，RTT 采样多了一段延迟。发送端没法知道这两个 RTT 样本的差异来自网络变化还是来自确认策略不同——丢包检测的时间阈值因此变得不可靠。

这两个矛盾加在一起，指向同一个结论：**不同加密阶段必须拥有独立的编号空间。** 各空间有自己的 PN 序列、自己的确认状态、自己的 RTT 采样，废弃时整体清除，不互相干扰。

QUIC 把这个设计叫做 **Packet Number Space**。

---

## 14.2 三个空间的角色、诞生与废弃

QUIC 定义了三个独立的 Packet Number Space：**Initial**、**Handshake**、**Application**。

**Initial Space** 是最先登场的。客户端发出第一个 Initial 包时，这个空间就诞生了。它承载的是 TLS ClientHello 和 ServerHello——握手的起点。Initial 密钥是从连接 ID 派生的公开密钥，安全性有限，因此这个空间的使命是"尽快完成引导、尽快退出"。一旦 Handshake 密钥安装完毕，Initial Space 就失去了存在意义。

**Handshake Space** 紧随其后。TLS 的密钥交换消息——Certificate、CertificateVerify、Finished——通过这个空间的包传输。Handshake 密钥提供了更强的保护，但它仍然不是最终状态。这个空间存活到握手完成、Application 密钥就绪为止。

**Application Space** 是最终接管者。一旦 TLS 握手完成，所有业务数据——HTTP 请求、响应、Stream Frame、控制帧——都通过这个空间传输。它的生命周期从握手完成一直延伸到连接关闭。

一个值得注意的事实是：**0-RTT 包和 1-RTT 包共享同一个 Application Space。** 这初看有些反直觉——0-RTT 和 1-RTT 用的明明是不同的密钥。但 Packet Number Space 的划分依据不是"密钥是否相同"，而是"确认状态是否需要隔离"。0-RTT 数据在握手完成后会自然过渡到 1-RTT 阶段，它们的确认状态需要连续衔接，不需要隔离。如果给 0-RTT 单独开一个空间，握手完成后还要做一次空间合并——复杂度增加了，收益为零。

quicX 的代码验证了这一点：`CryptoLevel2PacketNumberSpace()` 函数中，`kEarlyDataCryptoLevel`（0-RTT）和 `kApplicationCryptoLevel`（1-RTT）使用 case 穿透，都映射到 `kApplicationNumberSpace`。

握手进行中，一个连接会**同时维护多个 Space 的确认状态**。客户端在收到 ServerHello 之后、握手完成之前，可能同时在等 Initial 包的 ACK 和 Handshake 包的 ACK。这种并行是 QUIC 握手设计的自然结果——三个 Space 不是严格串行的，而是有时间上的重叠。

**废弃（Discard）是 Space 生命周期的重要一环。** 当更高加密级别的密钥安装完毕，旧 Space 不是"慢慢淡出"，而是被主动清除。RFC 9000 §4.10 规定：丢弃一个 PN Space 意味着放弃该空间中所有未确认包的状态——不再等待它们的 ACK，不再判断它们是否丢失，不再尝试重传。如果某些握手数据确实还没传完，协议会在新的加密级别下重传，不会继续在旧空间里补。

这个废弃机制反过来解释了为什么 Space 必须独立：如果所有阶段混在一个编号空间里，你没法安全地"把旧阶段的状态清掉但保留新阶段的状态"——因为它们的 PN 混在同一个列表里，你分不清哪些该清、哪些该留。独立的 Space 让废弃变成了一个干净的整体操作：清掉整个空间的 PN 记录、ACK 状态、ECN 计数器，完事。

把三个空间的生命周期放到时间线上看，整个画面更清晰：

```
时间 ─────────────────────────────────────────────────────────────→

客户端                              服务端
  │                                   │
  │─── Initial ClientHello ──────────→│
  │                                   │
  │  ┌─────────────────────────────┐  │
  │  │     Initial Space 存活       │  │
  │  │  PN: 0, 1, 2 ...            │  │
  │  └─────────────┬───────────────┘  │
  │                │                  │
  │←── Initial ServerHello ──────────│
  │                │                  │
  │  ┌─────────────┼───────────────┐  │
  │  │  Handshake Space 存活        │  │
  │  │  PN: 0, 1, 2 ...            │  │
  │  └─────────────┼───────────────┘  │
  │                │                  │
  │  ┌─────────────┼───────────────┐  │
  │  │  [0-RTT] Application Space  │  │
  │  │  共享 PN: 0, 1, 2 ...       │  │
  │  └─────────────┼───────────────┘  │
  │                │                  │
  │   ◆ Handshake 密钥安装           │
  │   ✕ Initial Space 废弃           │
  │     （清除全部 Initial 状态）      │
  │                │                  │
  │   ◆ 握手完成                     │
  │   ✕ Handshake Space 废弃         │
  │     （清除全部 Handshake 状态）    │
  │                │                  │
  │  ┌─────────────┼──────────────────────────────────────────┐
  │  │  Application Space [1-RTT] 持续运行直到连接关闭          │
  │  │  PN: 继续递增（与 0-RTT 连续）                          │
  │  └────────────────────────────────────────────────────────┘
```

注意几个要点：Initial Space 和 Handshake Space 在时间上有重叠——这不是错误，而是握手推进的自然结果。Application Space（如果有 0-RTT）甚至可能和 Initial Space 同时存活。但每个 Space 的废弃都是独立的、完整的——清掉整个空间的状态，不影响其他空间继续运转。

---

## 14.3 ACK Frame 的确认语言与信号能力

Packet Number Space 定义了确认的边界。ACK Frame 是在这个边界内表达确认信息的具体语言。

### 确认的是 Packet Number，不是字节位置

TCP 的 ACK 确认的是字节序号——"我已经收到字节流中 N 之前的所有数据"。QUIC 的 ACK 确认的是 Packet Number——"我收到了这些编号的包"。这个差异的根源在第 13 章已经讲过：QUIC 把确认层和交付层分离了。Packet Number 只标记"一次发送事件"，不携带字节流位置信息。数据在字节流中的位置由 Stream Offset 负责，和 PN 无关。

### 比 TCP 更丰富的确认表达

一个常见的误解是"QUIC 不使用累计确认"。实际上，QUIC 的 ACK Frame 既有累计确认的成分，也有选择确认的成分——它比 TCP 的两者都更强。

一个 ACK Frame 的核心结构是：

```
Largest Acknowledged    // 最大已确认 PN
First ACK Range         // 从 Largest 往前连续确认的包数
[Gap, ACK Range]*       // 后续的间隔 + 连续确认范围
```

`Largest Acknowledged` + `First ACK Range` 构成了"从最大已确认 PN 往前连续确认"的范围。如果接收端收到了 PN 10、11、12、13，`Largest Acknowledged = 13`，`First ACK Range = 3`，表示 PN 10-13 都收到了。这本质上就是一种累计确认——只不过起点是"最大已确认 PN"而不是"最小连续序号"。

后续的 `[Gap, ACK Range]*` 对提供了类似 TCP SACK 的能力。如果接收端收到了 PN 1-3 和 PN 7-10（中间的 4-6 没收到），ACK Frame 会用两段 Range 来表达这个地图：一段覆盖 7-10，一段覆盖 1-3，中间用 Gap 标记缺失的部分。

发送端拿到这张地图，立刻就能看出"PN 4、5、6 不在任何 Range 里"——可以直接判断它们可能丢失，不需要等待超时。TCP 的基本 ACK 只说"最大连续序号 3"，发送端知道 3 之前的都到了，但对 3 之后的乱序到达一无所知（除非有 SACK 选项）。QUIC 把 SACK 的能力内建到了 ACK Frame 的基本结构中，不是可选扩展，而是默认语言。

用一个具体例子把 ACK Frame 的构建过程走一遍。假设接收端收到了 PN 1, 2, 3, 7, 8, 9, 10, 15, 16：

```
接收端的 PN 集合（降序）: {16, 15, 10, 9, 8, 7, 3, 2, 1}

构建过程：
  Largest Acknowledged = 16
  First ACK Range = 1         → 覆盖 PN 15-16（连续 2 个，range值=1）

  Gap = 4                     → 跳过 PN 11-14（4 个缺失）
  ACK Range = 3               → 覆盖 PN 7-10（连续 4 个，range值=3）

  Gap = 3                     → 跳过 PN 4-6（3 个缺失）
  ACK Range = 2               → 覆盖 PN 1-3（连续 3 个，range值=2）

最终 ACK Frame:
  ┌──────────────────────────────────────┐
  │ Largest Acknowledged = 16            │
  │ ACK Delay = ...                      │
  │ ACK Range Count = 2                  │
  │ First ACK Range = 1                  │
  │ Gap = 4,  ACK Range = 3             │
  │ Gap = 3,  ACK Range = 2             │
  └──────────────────────────────────────┘

发送端看到的接收地图：
  PN:  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16
       ✓  ✓  ✓  ✕  ✕  ✕  ✓  ✓  ✓  ✓  ✕  ✕  ✕  ✕  ✓  ✓
```

发送端只需要扫描 Gap 对应的区间——PN 4-6 和 PN 11-14——就能定位所有可能丢失的包。相比之下，TCP 的累计 ACK 只能说"最大连续序号 3"，PN 7-10 和 15-16 的到达信息完全丢失。即使 TCP 启用了 SACK 选项，SACK 块数也受限于 TCP 选项空间（通常最多 3-4 个 SACK 块），而 QUIC 的 ACK Range 可以容纳多达数十个区间。

在 QUIC 的世界里，**乱序到达是常态而不是例外**。多个 Stream 并行传输，某个 Stream 的包可能比另一个 Stream 的包先到达。ACK Range 的设计让 QUIC 可以精确描述这种乱序格局，发送端据此做出更快、更准确的丢包判断。

### ACK 不只是确认，还是反馈信号

ACK Frame 携带的信息远不止"哪些包到了"。它同时是整个可靠性和性能系统的共同输入源。

**RTT 观测。** 发送端记录每个 Packet 的发送时间。当收到 ACK 确认了 Largest Acknowledged 那个 PN 时，用当前时间减去那个 PN 的发送时间，就是这一轮的原始 RTT。因为 PN 永不复用（第 13 章讲过的设计），每个 ACK 都能无歧义地对应到一次发送——RTT 采样永远是干净的。

**ACK Delay。** ACK Frame 里有一个 `ack_delay` 字段，记录接收端从收到 Largest Acknowledged 的包到发出这个 ACK 之间的延迟。发送端在计算 RTT 时需要减去这个延迟：`RTT = ACK到达时刻 - 发送时刻 - ACK Delay`。如果不扣除 ACK Delay，接收端的处理延迟会被算进网络延迟，导致 RTT 偏大、拥塞控制误判。

**ECN 反馈。** QUIC 有两种 ACK 帧类型：`AckFrame`（帧类型 0x02）和 `AckEcnFrame`（帧类型 0x03）。`AckEcnFrame` 继承了 `AckFrame` 的全部确认能力，额外携带三个计数器——`ect_0`、`ect_1`、`ecn_ce`。当路由器队列拥塞时，它会在数据包的 IP 头上标记 ECN CE（Congestion Experienced）。接收端统计收到的 CE 标记数量，通过 `AckEcnFrame` 报告给发送端。发送端据此主动缩小拥塞窗口——这是比"等丢包再反应"更早、更温和的拥塞响应。

**不同 Space 的确认策略。** 不是所有包都用同样的节奏确认。Initial 和 Handshake 空间的包必须立即确认——握手推进不能有延迟。Application 空间的包则允许延迟确认——接收端可以攒几个 ack-eliciting 包后再发一个 ACK，或者等到收到乱序包、ECN CE 标记时才立即回应。这种差异化策略既保证了握手的低延迟，又减少了稳定传输阶段的 ACK 开销。

ACK 是丢包检测、RTT 计算、拥塞控制的共同输入。确认边界的严格隔离——Initial 的 ACK 只确认 Initial 包，Handshake 的 ACK 只确认 Handshake 包，Application 的 ACK 只确认 Application 包——保证了每个 Space 内的反馈信号不被其他阶段的干扰所污染。

---

## 14.4 quicX 的确认账本

quicX 的确认职责被拆分到收发两端：**`RecvControl` 负责生成 ACK，`SendControl` 负责处理 ACK。** 不存在一个集中的"ACK 跟踪模块"——这个分工反映了一个事实：生成 ACK 的信息来自接收端的包到达记录，处理 ACK 的信息来自发送端的包发送记录，两者的数据来源和消费方向完全不同。

### RecvControl：接收端的确认状态

`RecvControl` 为每个 Packet Number Space 维护一套独立的接收记录。核心数据结构是三个平行数组：

- `wait_ack_packet_numbers_[kNumberSpaceCount]`——`std::set<uint64_t>` 类型，每个空间一个有序集合，记录所有已收到但还未通过 ACK 报告给对端的 PN。
- `pkt_num_largest_recvd_[kNumberSpaceCount]`——每个空间记录迄今为止收到的最大 PN，用于填充 ACK Frame 的 `Largest Acknowledged` 字段。
- `largest_recv_time_[kNumberSpaceCount]`——最大 PN 的接收时间，用于计算 ACK Delay。

当 `MayGenerateAckFrame()` 被调用时，它从 `wait_ack_packet_numbers_` 集合中取出所有待确认的 PN，按降序扫描构建连续区间——每段连续 PN 构成一个 ACK Range，两段之间的间隔构成 Gap。Range 数量上限为 64 个。如果当前连接启用了 ECN，生成的是 `AckEcnFrame`（帧类型 0x03），额外附带 `ect0_count_`、`ect1_count_`、`ce_count_` 三个计数器；否则生成普通 `AckFrame`（帧类型 0x02）。

**确认策略的差异化在 `ShouldSendImmediateAck()` 中体现。** 如果当前包属于 Initial 或 Handshake 空间——立即确认，不等。如果属于 Application 空间，则检查一系列条件：收到了 ECN CE 标记？乱序到达（PN 小于当前 largest）？有间隙（PN 跳过了某些编号）？累积了两个以上 ack-eliciting 包？任何一个条件成立就立即确认；否则启动延迟定时器，等一段时间后再发 ACK。

### SendControl：发送端的确认状态

`SendControl` 管理的是"我发出去的包，对端确认了哪些"。核心数据结构也是三个平行数组：

- `unacked_packets_[kNumberSpaceCount]`——`std::unordered_map<uint64_t, PacketTimerInfo>` 类型，记录每个已发送但未确认的包。`PacketTimerInfo` 包含发送时间、包长度、包内帧列表——这些信息在判丢时决定"丢了什么语义"，在 RTT 计算时提供"发送时刻"。
- `pkt_num_largest_acked_[kNumberSpaceCount]`——每个空间的最大已确认 PN，用于丢包检测的包间隔阈值判断。

当收到一个 ACK Frame 时，`OnPacketAck()` 的处理流程是：

```
收到 ACK Frame
     │
     ▼
① 解析 Largest Acknowledged + First ACK Range + Additional Ranges
     │
     ▼
② 更新 pkt_num_largest_acked_[ns]
     │
     ▼
③ 计算 RTT：用 Largest 对应的 send_time_ 和当前时间
   RTT = now - send_time - (ack_delay << ack_delay_exponent)
     │
     ▼
④ [如果是 AckEcnFrame] 验证 ECN 计数器单调递增
     │
     ▼
⑤ 遍历所有 ACK Range，逐 PN 从 unacked_packets_[ns] 中移除
   （状态从"在途"变为"已确认"）
     │
     ▼
⑥ 调用 DetectLostPackets()
   对剩余未确认包做丢包判定
```

每一步的细节：

1. 解析 ACK Frame 中的 Largest Acknowledged、First ACK Range 和所有 Additional ACK Ranges。
2. 更新 `pkt_num_largest_acked_[ns]`。
3. 用 Largest Acknowledged 对应的 `PacketTimerInfo.send_time_` 和当前时间计算 RTT，减去 `ack_delay << ack_delay_exponent_` 得到校正后的 RTT。
4. 如果是 `AckEcnFrame`，验证 ECN 计数器的单调递增性——计数器不应回退，如果回退说明路径上的 ECN 支持出了问题。
5. 遍历所有 ACK Range，逐个 PN 从 `unacked_packets_[ns]` 中移除——这些包的确认状态从"在途"变为"已确认"。
6. 调用 `DetectLostPackets()`——对剩下的未确认包，用包间隔阈值（largest_acked - pkt_num ≥ 3）和时间阈值（9/8 × smoothed_RTT）做丢包判定。

判丢的具体算法是第 15 章的内容。这里只需要知道：`DetectLostPackets()` 的输入来自 ACK 更新后的确认状态，输出是一组被标记为丢失的包——它们会被送入恢复层决定"丢了什么语义、怎么恢复"。

### Space 废弃的工程实现

握手完成时，quicX 的客户端和服务端都会同时废弃 Initial 和 Handshake 两个空间：

```
recv_control_.DiscardPacketNumberSpace(kInitialNumberSpace);
recv_control_.DiscardPacketNumberSpace(kHandshakeNumberSpace);
send_control_.DiscardPacketNumberSpace(kInitialNumberSpace);
send_control_.DiscardPacketNumberSpace(kHandshakeNumberSpace);
```

`RecvControl::DiscardPacketNumberSpace()` 清除该空间的待 ACK 包号集合、最大已收 PN、ECN 计数器——全部归零。`SendControl::DiscardPacketNumberSpace()` 取消该空间所有未确认包的定时器，清空 unacked_packets 映射表，从丢失包列表中移除属于该空间的条目。

这是一个整体操作——整个空间的状态被一次性擦除，不影响其他空间。如果所有阶段混在一个编号空间里，这种干净的废弃是不可能做到的。

### 0-RTT 的映射

`PacketNumber` 类持有一个三元素数组 `cur_packet_number_[kNumberSpaceCount]`，每个空间独立计数。`NextPacketNumber(space)` 保证每个空间内的 PN 单调递增。

当需要将加密级别映射到 PN Space 时，`CryptoLevel2PacketNumberSpace()` 中的 switch-case 清楚地展示了规则：`kEarlyDataCryptoLevel`（0-RTT）和 `kApplicationCryptoLevel`（1-RTT）共用 `kApplicationNumberSpace`。这两个加密级别用不同的密钥，但共享同一个 PN 计数器和同一套确认状态——协议层面的"0-RTT 和 1-RTT 共享 Application Space"规则在代码中体现为一行 case 穿透。

---
