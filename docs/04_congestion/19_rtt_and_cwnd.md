# 19. 管道的容量：RTT 测量与拥塞窗口的第一原理

卷三把可靠传输的基座搭完了——ACK 确认、丢包探测、语义重传、发送管线，共同保证数据不会丢、丢了能补。但"送得到"和"送得又快又稳"是两件事。一条 100 Mbps 的链路摆在那里，如果发送方不加约束地往里灌数据，路由器队列先涨、时延后飙、最后丢包坍塌。拥塞控制要解决的，正是这个"管道能承载多少"的持续估计问题。

本章是卷四的起点。它不涉及任何具体算法——Reno、Cubic、BBR 分别留给第 20–22 章——而是先建立一套坐标系：RTT 测量告诉发送方"管道现在有多挤"，cwnd 和 bytes_in_flight 构成"还能不能继续发"的闸门，ACK 则同时充当可靠性确认和速率反馈。最后落到 quicX 的工程组织，看看这些观测量是怎么被统一面板喂给拥塞控制算法的。

---

## 19.1 管道不是抽象比喻：吞吐、时延与在途字节为什么会拧成一根绳

发送方面前有一条网络连接，链路带宽是确定的物理量。但"链路能跑 100 Mbps"不等于"连接此刻可以发 100 Mbps"——中间的路由器、交换机都有队列，数据不会瞬间从一端飞到另一端。

吞吐量和时延之间存在一种非线性关系。在途字节（bytes_in_flight）较少时，数据几乎不排队，时延接近链路物理传播时延；当 bytes_in_flight 接近管道容量（带宽 × RTT）时，队列开始形成，时延上升；当 bytes_in_flight 超过管道容量，队列爆满，路由器丢包，吞吐反而坍塌。

拥塞的本质就是管道被灌过了容量上限。拥塞控制的第一原理不是"惩罚丢包"，而是"别把管道灌爆"——丢包只是管道被灌爆之后的症状。真正的目标是在管道快要满之前就慢下来，通过持续测量管道的能力边界来主动调整发送速率。

QUIC 的拥塞控制建立在这个第一原理之上：持续测量网络管道的能力——带宽有多大、队列有多长、现在是不是已经开始积水——然后据此调整发送速率。

---

## 19.2 时间的刻度：RTT、min_rtt、rttvar 为什么是连接最敏感的神经

测量管道能力，最直接的指标是 RTT（Round-Trip Time）——一个数据包从发出去到收到确认的时间。

RTT 直接反映网络当前的拥塞程度。网络空闲时，RTT 接近链路的物理传播时延（propagation delay）——信号在光纤或铜线里跑一个来回的物理时间。网络开始拥塞时，数据在路由器的队列里排队等待，RTT 显著增加。RTT 的变化，就是网络拥塞程度的变化。

但只看瞬时 RTT 是不够的——网络有噪声，一次测量可能有随机波动。所以 QUIC 的 RTT 测量体系里有三个核心量：

min_rtt（最小 RTT）是观测到的 RTT 样本的最小值，代表路径的本底时延——这条路径在不排队的情况下能跑多快。后续所有 RTT 测量都可以和 min_rtt 做比较：当前 RTT 远大于 min_rtt，说明有排队发生。

rttvar（RTT 变量）是 RTT 样本的变化幅度。rttvar 小说明网络稳定，rttvar 大说明网络抖动厉害。

smoothed_rtt（平滑 RTT）是对 RTT 样本做指数加权平均后的值，消除单次测量的噪声，得到更稳定的"当前 RTT"估计。

这三个量共同构成拥塞控制的感知面板。下面这张图展示了它们之间的关系：

```
RTT 值
  │
  │   ┌─ smoothed_rtt ──────── 跟踪当前网络状态
  │   │    ↕ rttvar            反映波动幅度
  │   │
  │   └─ min_rtt ────────────── 路径本底时延（不排队时的下限）
  │
  └──────────────────────────────────────→ 时间
       ← 空闲 →  ← 轻载 →  ← 拥塞加重 →
```

RFC 9002 §5.1 规定了 RTT 样本的生成规则：发送端在收到 ACK 时，用 ACK 帧中最大被确认包的发送时间来计算：

```
latest_rtt = ack_time - send_time_of_largest_acked
```

注意两个关键细节。第一，RTT 样本只从最大被确认包生成，避免对同一个包产生多个样本。第二，计算时需要扣除接收端的 ACK 延迟——接收端为了合并多个 ACK 会刻意延迟发送，这段等待时间不应算进网络往返时间。RFC 9002 §5.3 规定，握手确认后，发送端取 ACK 帧声明的延迟与对端 max_ack_delay 的较小值作为扣除量，且只有当 latest_rtt ≥ min_rtt + ack_delay 时才执行扣除，避免把 RTT 算到物理时延以下。

这里值得注意 QUIC 相比 TCP 的一个结构性优势。TCP 使用累计序号，重传的段和原始段共享同一个序号，发送方无法区分 ACK 确认的是原始发送还是重传——这就是经典的"重传歧义"（retransmission ambiguity）问题，它会污染 RTT 样本。QUIC 的包编号（Packet Number）是单调递增的，即使重传也使用新编号，天然避免了这个歧义，每个 RTT 样本都干净可靠。

计算出 RTT 样本后，QUIC 按 RFC 9002 §5.2–§5.3 更新三个核心量：

```
min_rtt     = min(min_rtt, latest_rtt)
smoothed_rtt = 7/8 × smoothed_rtt + 1/8 × adjusted_rtt
rttvar       = 3/4 × rttvar + 1/4 × |smoothed_rtt - adjusted_rtt|
```

7/8 和 3/4 是指数加权移动平均（EWMA）的系数——新样本只占 1/8 的权重，旧的历史值占 7/8，既平滑噪声又能跟踪趋势。

这三个量帮助发送端区分"只是慢了"和"开始挤了"。RTT 略微波动但整体接近 min_rtt，说明网络还行；RTT 持续高于 min_rtt 并继续上升，说明队列正在形成。RTT 告诉发送端的不是"数据到没到"，而是"网络现在有多挤"。

---

## 19.3 看不见的闸门：cwnd 与 bytes_in_flight 到底在限制什么

RTT 是"观测网络"的窗口，cwnd（拥塞窗口）和 bytes_in_flight（在途字节）则是"控制发送"的闸门。

bytes_in_flight 是"已经发出去但还没收到 ACK 的数据量"——当前正在网络里飞着的字节数。每发送一个 Packet，bytes_in_flight 增加；每收到一个 ACK，bytes_in_flight 减少。它反映的是当前实际占用的管道体积。

cwnd 是发送端给自己设的上限——"我最多允许自己有这么多数据在飞行"。不同的拥塞控制算法（Reno、Cubic、BBR）以不同方式调整 cwnd，但它的角色始终是一道不得超过的红线。

两者的关系决定了连接能不能继续发数据：

- bytes_in_flight < cwnd：还有预算，可以继续发新 Packet
- bytes_in_flight ≥ cwnd：达到管道容量上限，等 ACK 回来再继续

这就是发送的闸门逻辑——不是想发就发，而是要看 bytes_in_flight 是否碰到了 cwnd 这扇门。

用一个具体例子来说明。假设 cwnd = 14600 字节（10 个 MSS），当前 bytes_in_flight = 13140 字节（9 个包在飞行）：

```
                    cwnd = 14600 bytes (上限)
                    ┌───────────┐
  bytes_in_flight   │■■■■■■■■■□│  ← 还能再发 1 个包 (1460 bytes)
  = 13140 bytes     └───────────┘
                                      
  收到 ACK（确认 2 个包）后：

                    cwnd = 14600 bytes (不变)
                    ┌───────────┐
  bytes_in_flight   │■■■■■■■□□□│  ← 可以再发 3 个包
  = 10220 bytes     └───────────┘
```

不设这扇门会伤害自己。如果不顾 cwnd 限制拼命发——bytes_in_flight 超过网络实际容量——路由器队列爆满，大量丢包。丢包触发拥塞控制"刹车"，cwnd 大幅缩小，性能一夜回到解放前。cwnd 的本质不是保守，而是避免自我伤害。

RFC 9002 §7.2 规定了 cwnd 的初始值：连接建立时，cwnd 应该（SHOULD）设为 min(10 × max_datagram_size, max(14720, 2 × max_datagram_size))。以典型的 1460 字节 MSS 计算，初始 cwnd 约为 14600 字节（10 MSS）。连接只有在 bytes_in_flight < cwnd 时才被允许发送新数据包（RFC 9002 §7），PTO 探测包除外。

---

## 19.4 ACK 为什么不只是确认，也是速率反馈

卷三把 ACK 当作"确认哪些包到了"的工具。在卷四的语境下，ACK 还有另一重角色——速率反馈。

ACK 到达的节奏本身就包含网络状态信息。ACK 到达的间隔反映网络通畅程度：间隔短说明路径畅通，间隔长说明路径拥堵。ACK 确认的数据量反映网络的吞吐能力。RTT 的变化趋势——正是从 ACK 到达时间计算出来的——反映拥塞程度。

这引出一个重要概念：ACK 时钟（ACK Clock）。发送端有两种节奏控制：

- 发送时钟（Send Clock）：由 cwnd 和 bytes_in_flight 控制——bytes_in_flight < cwnd 时才能发
- ACK 时钟（ACK Clock）：由 ACK 到达控制——每收到一个 ACK，bytes_in_flight 减少，发送窗口松动一点

下面这张时间线展示了 ACK 时钟如何自然地控制发送节奏：

```
发送端                    网络                    接收端
  │                                                  │
  ├─ PKT 1 ──────────────────────────────────────→   │
  ├─ PKT 2 ──→                                       │
  ├─ PKT 3 ──→        (cwnd=3, 已满，等待)           │
  │    ⋮                                              │
  │  ←─────────────────────────────────── ACK 1 ──┤   收到 ACK 1
  ├─ PKT 4 ──→   (窗口松动，立即发)                  │
  │  ←────────────────────────────── ACK 2 ────┤      收到 ACK 2
  ├─ PKT 5 ──→                                       │
  │  ←─────────────────────────── ACK 3 ─────┤       收到 ACK 3
  ├─ PKT 6 ──→                                       │
```

ACK 时钟天然就是一种节流阀——ACK 回来得快，数据就发得快；ACK 回来得慢，数据就发得慢。网络本身在"告诉"发送端该以什么速度发。这就是拥塞控制中"自时钟"（Self-Clocking）特性的本质：用 ACK 的节奏来控制发送的节奏。

如果发送方不顾 ACK 时钟，一口气把 cwnd 允许的字节全部发出去，就会在网络某个节点形成瞬时队列，导致时延抖动。这就是"突发发送"（Burst）的问题——后面第 23 章要讲的 Pacer，正是为了对抗这种突发。

ACK 的速率反馈角色和可靠性确认角色是共存共生的。它们不是两个系统，而是同一套 ACK 机制的两个观测维度：

- 卷三的视角：哪些包到了、哪些包没到——丢包判断的输入
- 卷四的视角：ACK 的节奏怎么样、RTT 变了没有——拥塞控制的输入

恢复系统和拥塞控制共享同一个 ACK 反馈源，但服务不同目标：前者关心"包是否丢失"，后者关心"网络是否还能继续承载当前发送速率"。拥塞控制的核心不是"丢包后怎么办"，而是"怎么在丢包之前就感知到拥塞"——ACK 提供的 RTT 信息和节奏信息就是这个提前感知的关键。

---

## 19.5 quicX 的输入面板：RTT 观测与拥塞控制输入如何落到实现里

协议层的 RTT、cwnd、bytes_in_flight 讲清楚了，来看 quicX 怎么在代码里组织这些拥塞控制"输入"。

quicX 的拥塞控制有清晰的分层架构。

第一层是 RTT 观测层。`RttCalculator`（位于 `src/quic/connection/controler/rtt_calculator.h`）专门负责从 ACK 中提取 RTT 样本并更新三个核心量。它的状态面板非常直观：

```cpp
// quicX: src/quic/connection/controler/rtt_calculator.h
class RttCalculator {
    uint32_t latest_rtt_;      // 最近一次 RTT 样本
    uint32_t min_rtt_;         // 观测到的最小 RTT（路径本底）
    uint32_t smoothed_rtt_;    // 平滑 RTT（EWMA）
    uint32_t rtt_var_;         // RTT 变化量
    uint32_t pto_count_;       // PTO 退避指数
};
```

`UpdateRtt()` 的实现直接对应 RFC 9002 §5.2–§5.3 的公式。收到第一个 RTT 样本时：

```cpp
min_rtt_ = latest_rtt_;
smoothed_rtt_ = latest_rtt_;
rtt_var_ = latest_rtt_ >> 1;  // 初始 rttvar = latest_rtt / 2
```

后续样本按 EWMA 更新。注意 ack_delay 的处理——只有当 `latest_rtt_ >= min_rtt_ + ack_delay` 时才从样本中扣除，和 RFC 9002 §5.3 的规定一致：

```cpp
uint32_t adjusted_rtt = latest_rtt_;
if (latest_rtt_ >= (min_rtt_ + ack_delay)) {
    adjusted_rtt -= ack_delay;
}
smoothed_rtt_ = smoothed_rtt_ - (smoothed_rtt_ >> 3) + (adjusted_rtt >> 3);
```

第二层是拥塞控制接口层。`ICongestionControl`（位于 `src/quic/congestion_control/if_congestion_control.h`）定义了统一的拥塞控制接口，各种算法都实现这个接口。接口的核心方法分为三组：

```cpp
// quicX: src/quic/congestion_control/if_congestion_control.h
class ICongestionControl {
    // 事件输入：发包、收到 ACK、判丢
    virtual void OnPacketSent(const SentPacketEvent& ev) = 0;
    virtual void OnPacketAcked(const AckEvent& ev) = 0;
    virtual void OnPacketLost(const LossEvent& ev) = 0;

    // 发送控制：当前能不能发、能发多少
    enum class SendState { kOk, kBlockedByCwnd, kBlockedByPacing };
    virtual SendState CanSend(uint64_t now, uint64_t& can_send_bytes) const = 0;

    // 状态查询：cwnd、bytes_in_flight、是否在慢启动或恢复期
    virtual uint64_t GetCongestionWindow() const = 0;
    virtual uint64_t GetBytesInFlight() const = 0;
    virtual bool InSlowStart() const = 0;
    virtual bool InRecovery() const = 0;
};
```

`CanSend()` 返回的 `SendState` 枚举值得注意——它不是简单的 bool，而是明确告诉调用者"被谁阻塞了"：是 cwnd 不够（`kBlockedByCwnd`），还是 pacing 限速（`kBlockedByPacing`）。这在调试和可观测性上非常有价值。

第三层是 Pacer 接口。`IPacer`（位于 `src/quic/congestion_control/if_pacer.h`）负责把 cwnd 允许的发送量在时间维度上均匀摊开，避免突发。它的接口很简洁——`CanSend()` 判断当前能否发，`TimeUntilSend()` 返回距下次可发送的微秒数。Pacer 的具体实现留到第 23 章展开。

配置层面，quicX 的默认参数与 RFC 对齐：

```cpp
struct CcConfigV2 {
    uint64_t initial_cwnd_bytes = 10 * 1460;  // RFC 9002 §7.2: ~10 MSS
    uint64_t min_cwnd_bytes = 2 * 1460;       // RFC 9002 §7.2: 2 × max_datagram_size
    uint64_t mss_bytes = 1460;
    double beta = 0.5;                         // 丢包时 cwnd *= beta
};
```

这种分层的好处是关注点分离。`RttCalculator` 只负责"测得准"，不关心测来干什么。`ICongestionControl` 只关心"根据输入输出 cwnd"，不关心 RTT 怎么测。Pacer 只关心"发送节奏"，不关心 cwnd 怎么算。不管后面接 Reno、Cubic 还是 BBR，都能从同一个输入面板获取一致的数据。

```
                  ┌──────────────┐
   ACK 到达  ──→  │ RttCalculator │ ──→  min_rtt / smoothed_rtt / rttvar
                  └──────────────┘
                         │
                         ▼
              ┌─────────────────────┐
  发包/判丢 → │ ICongestionControl  │ → cwnd / bytes_in_flight / SendState
              │ (Reno/Cubic/BBR)    │
              └─────────────────────┘
                         │
                         ▼
                  ┌──────────┐
                  │  IPacer  │ → 发送时机 / pacing rate
                  └──────────┘
```

---

## 19.6 先学会量管道，后面才谈得上驯服它

回到本章的核心问题：QUIC 连接为什么不能只靠意愿发包，而必须持续测量这条网络管道到底能承受多少？

答案藏在管道的物理性质里。网络有容量上限，超过就排队、时延飙升、最终丢包。发送端必须通过 RTT、cwnd、bytes_in_flight 这些量，持续估计管道的能力边界，在快要满之前就慢下来。这不是保守，而是自我保护。

这也解释了拥塞控制和丢包恢复为什么是两件不同的事。丢包恢复关心"哪些包丢了，怎么补回来"；拥塞控制关心"网络还能不能继续发，发多快"。两者共享同一批观测源（ACK、RTT），但服务不同的控制目标。混淆它们，是理解拥塞控制最常见的障碍。

有了这套测量坐标系，一个更关键的问题浮出水面：当发送端检测到管道快满了——或者已经满了——它到底应该怎么调整 cwnd？减多少？恢复多快？用什么信号做判断？"丢包即拥塞"是最古老的回答，也是互联网拥塞控制的第一条道路。这条道路走了多远、又在哪里碰了壁，是下一章的故事。
