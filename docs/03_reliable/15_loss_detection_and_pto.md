# 15. 消失与追踪：丢包探测与 PTO 幽灵

第 14 章装好了 ACK 这套反馈体系——发送方终于能知道"谁到了"。但"谁到了"只是故事的一半。更棘手的另一半是：如果一个包始终没有出现在 ACK 里，它到底是丢了，还是只是迟到？

这个问题看似简单，实际上是整个可靠传输里最微妙的判断。网络不提供"包已丢失"的通知，发送方能做的只有基于已有证据做推断。推断太早，浪费带宽；推断太晚，卡死流水线。QUIC 的丢包探测算法，就是在这两种代价之间找平衡的工具。

本章从"沉默为什么不等于丢包"讲起，依次拆解时间阈值与包阈值的交叉验证、PTO 与传统 RTO 的本质差异、ack-eliciting packet 的过滤作用、多 Packet Number Space 的判丢复杂性，最后落到 quicX 中 `RttCalculator` 和 `SendControl` 的具体实现。

---

## 15.1 沉默不是证据："没有回音"为什么不等于"已经丢了"

想象一下：你发送了一个 Packet Number 为 5 的包，然后等啊等——ACK 始终没有来。直觉反应是"包丢了，重传吧"。但网络世界没那么简单。包没有立刻收到 ACK，可能有无数种原因：它在网络里排队等着处理，走了不同的路由路径，或者在某个交换机的缓冲区里多待了一会儿，甚至可能对端已经收到了但 ACK 在回程丢了。

网络里的沉默，可能意味着包真的丢了，也可能意味着包正在慢悠悠地赶来，还可能意味着 ACK 回程被堵住了。如果过早地判断"包丢了"并开始重传，你会浪费带宽——因为原始包可能还在网络上跑；如果过晚地判断丢包，你会浪费等待时间——应用数据卡在那里，整个传输流水线被迫停下来。

QUIC 面对这个问题的态度是：它不相信自己能观察到"丢包"这个事实，它只相信自己可以做出"包大概率已经丢了"的推断（RFC 9002 §6）。这是一个概率问题，不是一个观察结果。

这就是丢包探测（Loss Detection）的本质：发送方永远没办法 100% 确定一个包是丢了还是迟到——它只能根据已有的证据来推断最可能的答案。证据有两类：一是时间维度的"等了多久"，二是包序列维度的"后面的包到了几个"。QUIC 的判丢算法就是把这两类证据交叉验证，在不确定性中做最佳推断。

---

## 15.2 两把尺子：时间阈值与包阈值为什么要并存

QUIC 的丢包探测不靠单一信号，而靠两把尺子一起量：时间阈值（Time Threshold）和包阈值（Packet Threshold）。

先看包阈值。假设发送方连续发送了 PN 5、6、7、8、9、10 六个包，随后收到一个 ACK 确认了 PN 8、9、10。此时 PN 5 的情况是：它后面已经有三个更高编号的包被确认（8、9、10），而它自己始终没有出现在 ACK 里。三个包的间隔足够大，PN 5 大概率不是"正在路上"，而是真的丢了。

这就是包阈值的判断逻辑——RFC 9002 §6.1.1 将这个阈值定义为常量 `kPacketThreshold = 3`：当一个未确认的包后面已经有 3 个或更多更高编号的包被确认时，就将它判定为丢失。用一个 ASCII 时间线来说明：

```
发送方：   PN5 → PN6 → PN7 → PN8 → PN9 → PN10
                                 ↓      ↓       ↓
收到 ACK：                      PN8    PN9     PN10

判定：PN5 后面有 3 个包被确认（10 - 5 ≥ 3）→ 判丢 ✓
      PN6 后面有 3 个包被确认（10 - 6 ≥ 3）→ 判丢 ✓（10-6=4≥3）
      PN7 后面只有 2 个包被确认（10 - 7 = 3 ≥ 3）→ 判丢 ✓
```

为什么阈值是 3 而不是 1？因为网络天然存在乱序。如果后面只有 1 个包被确认就判丢，乱序到达的包会被频繁误判。3 个包的间隔在大多数网络条件下能有效区分"乱序"和"丢失"。

再看时间阈值。包阈值有一个盲区：如果发送方在某段时间只发了一个包，后面没有新包被确认，包阈值永远不会触发。这时候需要时间维度来兜底。RFC 9002 §6.1.2 定义了时间阈值的计算方式：

```
loss_delay = 9/8 × max(smoothed_rtt, latest_rtt)
```

含义是：如果一个未确认包的发送时间比最近被确认包的发送时间早了超过 `loss_delay`，就判定它已丢失。9/8 这个系数给 RTT 留了 12.5% 的余量，避免因为正常的 RTT 抖动而误判。

用一个时间线来说明时间阈值的工作方式：

```
时间轴：  0ms     50ms    100ms   150ms   200ms
          |        |        |       |       |
发送：   PN5     PN6      PN7     PN8
                                    ↓
收到 ACK(PN8)：                    此刻

smoothed_rtt = 80ms → loss_delay = 9/8 × 80 = 90ms
PN5 发送距 PN8 发送已过 150ms > 90ms → 判丢 ✓
PN6 发送距 PN8 发送已过 100ms > 90ms → 判丢 ✓
PN7 发送距 PN8 发送已过  50ms < 90ms → 暂不判丢
```

两把尺子捕捉的是不同类型的网络问题。时间阈值对长尾延迟更敏感——有些包就是会比其他包晚到很多；包阈值对突发丢包更敏感——网络突然丢了一个包，后续包仍然正常到达。QUIC 同时用两把尺子交叉验证，只要任意一个条件满足，就将包判定为丢失。

这不是故意复杂化，而是在主动对抗网络的不确定性。

---

## 15.3 超时不再只是等待：PTO 为什么比传统 RTO 更像现代网络的产物

当两把尺子都无法触发时——比如发送方发出一个包之后就没有再发新包，ACK 也没有回来——判丢逻辑陷入沉默。这时候需要另一种机制来打破僵局。

在传统 TCP 的世界里，这个机制叫超时重传（Retransmission Timeout，RTO）。RTO 像一个老式的厨房定时器——时间到了就响铃，你就知道该重发了。它的问题在于太"死板"：如果 RTO 设得太短，正常的网络抖动会频繁触发无意义的重传；如果设得太长，应用数据会卡在那里等待。更关键的是，TCP 的 RTO 到期后直接认定包已丢失，并且会将拥塞窗口重置到最小值——这对实际只是网络抖动的场景来说代价过重。

QUIC 引入了 PTO（Probe Timeout，探测超时）来替代这种思路。PTO 与 RTO 有一个根本区别：PTO 到期不意味着包丢失。RFC 9002 §6.2 明确说明——"A PTO timer expiration event does not indicate packet loss"。PTO 到期后，QUIC 不会将任何包标记为丢失，也不会重置拥塞窗口。它只做一件事：发送一到两个探测包（probe packet），目的是引出（elicit）对端的 ACK 回应。

RFC 9002 §6.2.4 进一步规定：探测包应当（SHOULD）包含新数据。如果没有新数据可发，才退而求其次重传旧数据，或者发送一个 PING 帧。探测包不是空洞的"你还在吗"，它是真正推进传输的手段——只不过它的首要目标是逼出一个 ACK，让判丢逻辑重新获得证据。

PTO 的计算公式（RFC 9002 §6.2.1）是：

```
PTO = smoothed_rtt + max(4 × rttvar, kGranularity) + max_ack_delay
```

其中 `kGranularity` 是定时器最小精度（通常 1ms），`max_ack_delay` 是对端声明的最大 ACK 延迟。这个公式的含义是：在正常 RTT 加上足够的抖动余量再加上对端的 ACK 延迟之后，如果 ACK 还没来，就该主动探测了。

PTO 还有指数退避（exponential backoff）机制：每次 PTO 到期但未收到 ACK，退避因子翻倍。第一次 PTO 到期等待 `PTO` 时间，第二次等待 `2 × PTO`，第三次 `4 × PTO`，以此类推。这防止了在持续丢包的网络里频繁发送探测包，给网络恢复留出空间。

下面这张表格总结了 PTO 与传统 TCP RTO 的核心差异：

| 维度 | TCP RTO | QUIC PTO |
|------|---------|----------|
| 到期含义 | 认定包已丢失 | 不认定丢失，只发探测 |
| 到期动作 | 重传原始段 + 重置 cwnd | 发送探测包（优先新数据） |
| 对拥塞窗口的影响 | 重置到 1 MSS | 不影响 cwnd |
| 退避机制 | 指数退避 | 指数退避（上限 2⁶ = 64 倍） |
| 作用范围 | 单连接 | 每个 Packet Number Space |

在握手期间，PTO 尤其重要。握手阶段的包（Initial、Handshake）承载着关键的 TLS 消息，如果丢包导致握手卡住，整个连接就悬在那里。QUIC 在握手期会使用更激进的 PTO 策略——在还没有 RTT 样本时使用初始 RTT（通常 250ms）作为 PTO 基准，并在每次 PTO 到期后快速重发握手数据。

在应用期，PTO 同样重要。即使连接已经稳定运行，网络状态也可能突然恶化——基站切换、WiFi 断开重连、路径变化。PTO 的持续探测让 QUIC 能够及时发现这些变化，而不是在沉默中无限等待一个永远不会来的 ACK。

PTO 的存在说明了一个设计态度：QUIC 不相信"沉默等于死亡"，它只相信自己主动探测到的信号。这也是标题里"幽灵"的含义——PTO 像一个始终在背后徘徊的影子，不断逼问网络："你还在推进吗？"

---

## 15.4 谁值得被等待：ack-eliciting packet 为什么如此关键

在 QUIC 的丢包探测里，有一个概念至关重要：ack-eliciting packet——能够引发对端发送 ACK 的包。

RFC 9000 §2 给出了定义：一个包如果包含至少一个 ack-eliciting frame，就是 ack-eliciting packet。哪些帧是 ack-eliciting 的？STREAM、CRYPTO、PING、NEW_CONNECTION_ID 等绝大多数帧都是。哪些不是？只有两种：ACK 帧和 PADDING 帧。

这意味着，一个只包含 ACK 帧的包不是 ack-eliciting packet——它的目的就是告诉对方"我收到了你的包"，它自己不需要被确认。一个只包含 PADDING 帧的包也不是——填充帧没有语义内容，不需要回应。

这种区分对丢包探测的意义在于：只有 ack-eliciting packet 才会纳入判丢逻辑的观察范围。如果你把 ACK-only 的包也纳入丢包探测，你会浪费大量时间追踪一些本来就不期望有回应的包。

PTO 的启动条件也与此相关：只有当有 ack-eliciting packet 在等待 ACK 时，PTO 定时器才会被激活（RFC 9002 §6.2.2）。如果发送方只发了一些 ACK-only 的包，PTO 不会为它们启动——因为它们本来就不会引发对端的 ACK 回应，等也是白等。

这就是"谁值得被等待"的含义：丢包探测和 PTO 不是盯着所有包，而是只盯着那些真正能引出回声的包。这让整个恢复系统的判断更快、更准确，不会被无关信号干扰。

---

## 15.5 多个空间里的失踪案：不同加密阶段为什么会让判丢更复杂

QUIC 有三个 Packet Number Space：Initial、Handshake、Application Data。每个空间有自己独立的包编号序列、自己的 ACK 状态，也有自己的丢包探测逻辑。这意味着丢包探测不是"一个全局算法跑一遍"，而是每个空间各自独立运行。

三个空间面临的判丢环境截然不同。

Initial 空间的样本密度最低。握手开始时，客户端通常只发出一个 Initial 包（承载 ClientHello），然后等待服务端的回应。在这个阶段，发送方没有足够的后续包来触发包阈值——因为根本没有"后面的包"可以充当参照物。时间阈值同样受限，因为 RTT 还没有任何测量样本，只能使用初始估计值（quicX 中默认 250ms）。所以 Initial 阶段几乎完全依赖 PTO 来推动探测。

Handshake 空间稍好一些，但仍然有限。此时已经有了一个 RTT 样本（从 Initial 交互中获得），时间阈值的计算有了依据。不过 Handshake 包的数量通常也不多——主要就是 TLS ServerHello 和 Finished 等几个消息——所以包阈值仍然很难触发。

Application Data 空间是最"正常"的场景。连接建立后，发送方可能有几十甚至几百个包在飞行中，RTT 样本充足，时间阈值和包阈值都能正常工作。但这个阶段的复杂性在于规模——大量在飞行中的包需要逐个检查是否满足判丢条件。

另一个影响判丢的因素是加密阶段的切换。当握手完成后，Initial 和 Handshake 空间的密钥会被丢弃（RFC 9001 §4.9）。一旦密钥丢弃，这两个空间里尚未确认的包就不可能再被重传了——因为对端已经无法解密它们。QUIC 的处理方式是：在密钥丢弃时，直接放弃这些空间的所有未确认包，不再为它们做丢包探测。quicX 中 `SendControl::DiscardPacketNumberSpace()` 就负责执行这个清理动作。

QUIC 的做法是每个 Packet Number Space 独立维护自己的丢包探测状态，但共享同一个 PTO 定时器框架。PTO 到期时，会优先为最早的 Packet Number Space 发送探测包。这样既保证了不同空间的探测需求，又避免了维护大量独立定时器的开销。

---

## 15.6 quicX 的追踪器：RTT、PTO 与探测逻辑如何落到实现里

协议层面的判丢逻辑讲清楚之后，来看 quicX 是怎么在代码里组织这套系统的。两个核心模块：`RttCalculator` 负责 RTT 估算和 PTO 计算，`SendControl` 负责包跟踪和判丢执行。

`RttCalculator` 的核心方法是 `UpdateRtt()`。每次收到 ACK，`SendControl::OnPacketAck()` 会用包的发送时间和当前时间算出一个 RTT 样本，然后交给 `UpdateRtt()` 进行平滑处理。平滑算法直接来自 RFC 9002 §5：

```
smoothed_rtt = 7/8 × smoothed_rtt + 1/8 × adjusted_rtt
rttvar       = 3/4 × rttvar       + 1/4 × |smoothed_rtt - adjusted_rtt|
```

其中 `adjusted_rtt` 是减去 ACK Delay 之后的样本值。`RttCalculator` 还维护了 `min_rtt_`（历史最小 RTT），用于判断 ACK Delay 是否应当被扣除——只有当 `latest_rtt >= min_rtt + ack_delay` 时才扣除，避免把 RTT 算成负值。

PTO 的计算由 `RttCalculator::GetPT0Interval()` 完成，对应 RFC 9002 §6.2.1 的公式：

```cpp
// PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
return smoothed_rtt_ + std::max<uint32_t>(rtt_var_ << 2, 1) + max_ack_delay;
```

指数退避在 `GetPTOWithBackoff()` 中实现：将基础 PTO 左移 `pto_count_` 位（等价于乘以 2^pto_count_），上限为 2⁶ = 64 倍。每次 PTO 到期，`OnPTOExpired()` 递增 `pto_count_`；收到 ACK 后，`OnPacketAcked()` 将其重置为 0。

判丢执行由 `SendControl::DetectLostPackets()` 负责。它在每次收到 ACK 后被调用，遍历对应 Packet Number Space 中所有未确认的包，逐个检查两个条件：

```cpp
// 包阈值判定（RFC 9002 §6.1.1）
static constexpr uint32_t kPacketThreshold = 3;
if (largest_acked >= pkt_num + kPacketThreshold) {
    should_declare_lost = true;
}

// 时间阈值判定（RFC 9002 §6.1.2）
static constexpr uint32_t kTimeThresholdNum = 9;
static constexpr uint32_t kTimeThresholdDen = 8;
uint64_t loss_delay = (smoothed_rtt * kTimeThresholdNum) / kTimeThresholdDen;
if (time_since_sent > loss_delay) {
    should_declare_lost = true;
}
```

任一条件满足即判丢。被判丢的包会被加入 `lost_packets_` 队列等待重传，同时通知拥塞控制模块调整窗口。

PTO 定时器的全局管理由 `SendControl::OnPTOTimer()` 完成。PTO 到期时，它执行以下流程：调用 `rtt_calculator_.OnPTOExpired()` 递增退避因子 → 在所有 Packet Number Space 中找到最早的未确认包 → 将其标记为丢失并触发重传回调 → 重新调度下一次 PTO 定时器。如果握手尚未完成且没有可重传的数据，它会通过 `probe_needed_cb_` 触发发送一个 PING 帧，确保握手不会因为沉默而永久卡住。

未确认包的跟踪结构是一个按 Packet Number Space 分组的哈希表 `unacked_packets_[ns]`，每个条目记录发送时间、包大小、定时器任务和包内容。ACK 到达时从表中移除；判丢时也从表中移除并加入重传队列。这就是"追踪器"的全貌——一个持续运转的观察系统，而不是一次性的判断。

---

## 15.7 先看见消失，才谈得上救赎

QUIC 丢包探测的轮廓到这里已经完整：ACK 给了坐标系，时间阈值和包阈值给了两把交叉验证的尺子，PTO 给了打破沉默的探针，ack-eliciting packet 过滤了无关信号，Packet Number Space 的独立维护保证了不同加密阶段各司其职。

回答本章的核心问题：QUIC 是怎么在一个充满乱序和抖动的世界里推断出包真的丢了？答案是——它不推断"事实"，它推断"概率"。它用包阈值抓突发丢包，用时间阈值抓长尾延迟，用 PTO 逼出沉默网络的回应。它不是在"发现丢包"，而是在"基于已有信息做出最合理的猜测"。

只有先定义了"什么时候算丢"，下一章的语义重传才有合法的起点——既然已经判定一个包失踪，接下来真正要回答的是：该重发的到底是包本身，还是包里承载的语义？
