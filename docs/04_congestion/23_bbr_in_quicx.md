# 23. 速度的手术台：quicX 中拥塞控制的工程实践

前三章走完了拥塞控制的三条思想道路——Reno 用丢包画出了互联网拥塞控制的第一条基线，Cubic 在高 BDP 场景下用三次函数把恢复速度提升了一到两个数量级，BBR 三代在"模型驱动"与"丢包妥协"之间反复校准。但这些都是论文和 RFC 里的故事。当它们真正被塞进一个协议库的代码里时，新的问题立刻浮出水面：五种算法怎么共处一套接口？论文里简洁的模型在工程化时会在哪里失真？知道窗口该多大，但一口气发出去和匀着发出去差距有多大？怎么证明实现没有"悄悄偏了"？

本章是卷四的收官章。六节依次覆盖：多算法共存的工程必然性与 quicX 的统一接口设计、BBR 三代从论文到代码的工程差异与实现陷阱、Pacer 在现代发送路径中不可替代的位置、工厂装配与连接级选择的配置体系、仿真与基准测试构成的验证闭环，以及卷四从第一原理到工程落地的完整弧线收束。

---

## 23.1 一座库，不止一种王法：为什么协议库要同时保留多种拥塞控制算法

第 22 章的结论已经充分论证了一个事实：没有一种拥塞控制算法在所有场景下都是最优的。但"没有银弹"在工程层面意味着什么？意味着协议库必须同时保留多种算法，并让每条连接可以独立选择。

多算法共存的需求来自真实网络的多样性。数据中心内部的连接——BDP 极小、丢包率极低——Reno 的 AIMD 足够用，简单可预测。跨大洲的长肥管道需要 Cubic 的三次函数恢复速度。移动网络上有深缓冲区导致的 bufferbloat，BBR 的模型驱动能显著压低排队时延。视频流、网页请求、大文件传输面对不同的网络条件，强制使用同一种算法只会在某些场景下表现优异、在另一些场景下严重退化。

"默认算法"是工程决策，不是信仰。quicX 当前的默认选择是 Cubic——它在有线网络上久经验证、行为可预测、与 Linux TCP 栈的 Cubic 共存时最公平。但 BBR v3 在浅缓冲区和随机丢包场景下有结构性优势，而 Reno 在超低延迟数据中心里是最低开销的选择。默认值只是"没有更多信息时的安全选择"，不等于"唯一正确的选择"。

quicX 的工程方案是把所有算法收束到一个统一的抽象接口之下。`ICongestionControl`（位于 `src/quic/congestion_control/if_congestion_control.h`）定义了拥塞控制算法必须实现的完整契约：

```cpp
// quicX: src/quic/congestion_control/if_congestion_control.h
class ICongestionControl {
    // 事件输入：发包、ACK 确认、判丢、RTT 采样
    virtual void OnPacketSent(const SentPacketEvent& ev) = 0;
    virtual void OnPacketAcked(const AckEvent& ev) = 0;
    virtual void OnPacketLost(const LossEvent& ev) = 0;
    virtual void OnRoundTripSample(uint64_t latest_rtt, uint64_t ack_delay = 0) = 0;

    // 发送控制
    enum class SendState { kOk, kBlockedByCwnd, kBlockedByPacing };
    virtual SendState CanSend(uint64_t now, uint64_t& can_send_bytes) const = 0;

    // 状态查询
    virtual uint64_t GetCongestionWindow() const = 0;
    virtual uint64_t GetBytesInFlight() const = 0;
    virtual uint64_t GetPacingRateBps() const = 0;
    virtual bool InSlowStart() const = 0;
    virtual bool InRecovery() const = 0;
    virtual uint64_t GetSsthresh() const = 0;
};
```

这套接口的设计有几个值得注意的工程决策。

第一，事件输入采用结构体传参。`SentPacketEvent` 携带包编号、字节数、发送时间和是否重传；`AckEvent` 携带确认的包编号、字节数、确认时间、ACK 延迟和 ECN-CE 标记；`LossEvent` 携带丢失包的编号、字节数和判丢时间。结构体传参而非分散的参数列表，既方便后续扩展新字段，又避免了方法签名因算法差异而膨胀。

第二，`CanSend()` 返回的是三态枚举（`kOk` / `kBlockedByCwnd` / `kBlockedByPacing`），而不是简单的 bool。这个设计让发送路径和调试系统能够区分"被窗口挡了"和"被节奏限速了"——两种阻塞的含义完全不同，处理策略也不同。`kBlockedByCwnd` 意味着网络管道已经满载，需要等 ACK 释放空间；`kBlockedByPacing` 意味着管道还有余量，但 Pacer 要求匀速发送，稍后即可。

第三，`GetPacingRateBps()` 被放在统一接口中。Reno 和 Cubic 并不像 BBR 那样直接输出 pacing rate，但 quicX 仍然让所有算法都提供这个查询——Reno/Cubic 的 pacing rate 由 cwnd / smoothed_rtt 推算而来，BBR 由模型直接给出。统一接口意味着 Pacer 不需要知道上游是哪种算法，只需要读取这个值就能工作。

这套接口让连接层完全不需要关心"当前跑的是 Reno 还是 BBR"。连接只和 `ICongestionControl*` 打交道——发包时调 `OnPacketSent`，收到 ACK 调 `OnPacketAcked`，判丢时调 `OnPacketLost`，发送前问 `CanSend`。五种算法在接口之上完全平等，新算法的接入只需要实现这套接口、注册到工厂，不需要改动连接层一行代码。

---

## 23.2 从论文到代码：BBR v1 / v2 / v3 的工程差异与实现陷阱

第 22 章讲透了 BBR 三代的设计思想演进。这一节不重复算法原理，而是聚焦一个工程问题：**从论文到代码的过程中，最容易在哪些地方出问题。**

quicX 同时维护了三个 BBR 版本的完整实现——`BBRv1CongestionControl`、`BBRv2CongestionControl`、`BBRv3CongestionControl`（分别位于 `src/quic/congestion_control/bbr_v1_congestion_control.h/.cpp`、`bbr_v2_congestion_control.h/.cpp`、`bbr_v3_congestion_control.h/.cpp`）。三个版本都实现了同一套 `ICongestionControl` 接口，但内部复杂度逐代递增。

**v1 的工程核心：BtlBw 滑动窗口过滤器和四种模式。**

v1 内部维护一个 `max_bw_filter_`——过去若干轮次中观测到的最大带宽的滑动窗口最大值过滤器（`kBwWindow = 10` 轮次）。这个过滤器是 v1 带宽估计的全部基础，也是工程上最危险的单点：如果某一轮因为偶发条件（比如其他流进入 ProbeRTT 暂时让出带宽）观测到了一个偏高的值，这个偏高值会在过滤器中"锁定"长达 10 个轮次。在这段时间里，v1 的发送速率会持续偏高——这就是 inflight 膨胀的工程根源。

v1 的四种模式（Startup / Drain / ProbeBW / ProbeRTT）的状态管理在概念上清晰，但工程实现中边界条件处处是陷阱。Startup 的退出判据"带宽估计连续三轮不增长"需要精确跟踪轮次边界——什么算"一轮"？是固定时间间隔还是 inflight 数据全部被确认？ProbeRTT 每 10 秒把 cwnd 降到 4 个 MSS、持续 200ms——在高带宽链路上这意味着吞吐量骤降 99%+，如果退出 ProbeRTT 时的 BtlBw 估计已经过时，恢复过程会异常缓慢。

**v2 的增量：inflight_hi / inflight_lo 的双限制。**

v2 引入了 `inflight_hi_bytes_` 和 `inflight_lo_bytes_` 两个状态变量。工程上的关键区别在于，v2 的 cwnd 目标不再是简单的 `cwnd_gain × BDP`，而是 `min(cwnd_gain × BDP, inflight_hi)`。这个 `min` 操作是一行代码的事，但它从根本上改变了算法的行为——inflight 膨胀被截断了。

v2 还引入了丢包轮次追踪（`loss_event_count_in_round_`）。从工程角度看，"追踪丢包轮次"的困难不在于计数器本身，而在于如何正确定义"轮次"的边界——ACK 乱序到达时，同一轮次内的多次丢包应该被合并还是分别计数？这个判断直接影响 inflight_hi 的衰减频率。

**v3 的完整度：ProbeBW 四子状态和 loss-based bound。**

v3 是三个版本中状态机最复杂的。ProbeBW 被拆分为四个子状态（DOWN / CRUISE / REFILL / UP），每个子状态有独立的进入条件、退出判据和增益设置。状态转换的正确性验证是 v3 工程实现中最耗时的部分——四个子状态之间的切换条件涉及 inflight 水位、BtlBw 变化率、丢包率统计，任何一个条件判断的 off-by-one 错误都可能导致某个子状态被跳过或陷入。

v3 的 loss-based bound 引入了三个关键参数：`loss_threshold_(0.02)`、`beta_loss_(0.9)`、`beta_ecn_(0.85)`。这些不是可以随意调整的"配置参数"，而是算法收敛性的根基。`loss_threshold` 定义了"统计上显著的丢包率"——低于 2% 的丢包被视为随机噪声不予响应。`beta_loss` 和 `beta_ecn` 分别控制丢包和 ECN 触发的 inflight_hi 衰减幅度。修改这些值需要完整的仿真验证，否则可能破坏算法与 Cubic 的公平性收敛。

**从论文到代码最容易出的四类失真：**

```
失真类型              论文假设                 工程现实
──────────────────────────────────────────────────────────
带宽估计窗口          "近期最大带宽"           偶发高值被锁定，偏高持续多轮
状态转换边界          "当 inflight ≤ BDP"      BDP 本身是估计值，±10% 误差常见
ProbeRTT 触发        "每 10s 降低 cwnd"       高带宽下骤降 99%，应用层感知明显
整数精度              "连续实数运算"           高带宽场景下 uint64 溢出风险
```

第一类，带宽估计的时间窗口选择影响灵敏度。窗口太长，对带宽变化响应迟钝；窗口太短，容易被瞬时波动误导。v1 的 10 轮窗口在稳定网络中合理，但在带宽剧烈波动的移动网络上可能记住过时的高值。

第二类，状态转换的边界条件处理。"inflight 降到 BDP 以下时退出 DOWN"——但 BDP 本身是 BtlBw × RTprop 的乘积，两个估计值都有误差。如果 BDP 估计偏低，DOWN 会过早退出，路径上仍有残留队列；如果偏高，DOWN 持续时间过长，浪费吞吐量。

第三类，ProbeRTT 的触发时机和窗口降低幅度。v1 的 4 MSS 在 1 Gbps 链路上意味着 cwnd 从约 6.25 MB 骤降到不足 6 KB，持续 200ms。对延迟敏感的应用（实时视频、游戏）来说，这 200ms 的吞吐骤降是可感知的。

第四类，高带宽场景下的整数精度。pacing rate 的单位是 bytes/sec，在 100 Gbps 链路上这个值约为 12.5 × 10⁹——已经接近 uint64 的有效精度边界。乘法运算中的中间结果溢出是高带宽场景下最隐蔽的 bug 来源。

---

## 23.3 节奏感来自哪里：Pacer 在现代发送路径中的位置

拥塞控制算法的输出是"这一轮能发多少字节"（cwnd）和"发送速率应该是多少"（pacing rate）。但知道"能发多少"和"怎么发出去"是两回事。

没有 Pacer 时，发送方的行为是突发的。cwnd 打开后，发送方会在一个 RTT 的开头把整个窗口的数据尽快发出——网卡能多快就多快。这种突发会在网络某个节点瞬间形成队列：即使总量没超过 cwnd，瞬时速率远高于瓶颈带宽也会打满缓冲区。

```
无 Pacer（突发发送）：                   有 Pacer（匀速发送）：

发送速率                                 发送速率
  │ ████                                   │ ─────────────────
  │ ████   ← 瞬间打满                      │ ← 匀速，≈ 瓶颈带宽
  │ ████                                   │
  │                                        │
  │          (等 ACK)                      │
  └──────────────→ 时间                    └──────────────→ 时间
     一个 RTT                                  一个 RTT
```

突发带来三个工程后果。第一，瞬时排队导致 RTT 测量被污染——某些包排了队、某些没有，RTT 样本噪声增大。第二，缓冲区瞬间爆满可能引发不必要的丢包——即使平均发送速率没有超过带宽。第三，对 BBR 来说尤其致命——BBR 的模型假设发送速率 ≈ BtlBw，如果实际发送是突发的，带宽估计会被突发的 ACK 聚集效应带偏。

quicX 的 `IPacer` 接口（位于 `src/quic/congestion_control/if_pacer.h`）定义了 Pacer 的职责边界：

```cpp
// quicX: src/quic/congestion_control/if_pacer.h
class IPacer {
    virtual void OnPacingRateUpdated(uint64_t pacing_rate) = 0;  // 拥塞控制更新速率
    virtual bool CanSend(uint64_t now) const = 0;                // 当前能否发送
    virtual uint64_t TimeUntilSend() const = 0;                  // 距下次可发送的微秒数
    virtual void OnPacketSent(uint64_t sent_time, uint64_t bytes) = 0;  // 记录发包
    virtual void Reset() = 0;                                    // 重置状态
};
```

`NormalPacer`（位于 `src/quic/congestion_control/normal_pacer.h/.cpp`）是 quicX 中 Pacer 的标准实现。它的核心是一个令牌桶模型，用五个状态变量控制发送节奏：

```cpp
// quicX: src/quic/congestion_control/normal_pacer.h
class NormalPacer : public IPacer {
    uint64_t pacing_rate_bytes_per_sec_;  // 当前发送速率
    uint64_t next_send_time_ms_;          // 下次允许发送的绝对时间
    uint64_t last_update_ms_;             // 上次 burst budget 补充时间
    uint64_t max_burst_bytes_;            // 最大突发字节数（默认 16KB）
    uint64_t burst_budget_bytes_;         // 当前突发预算
};
```

`burst_budget_bytes_` 是 Pacer 最精妙的设计。严格的匀速发送会让每个包都必须等待——即使网络完全空闲，第一个包也得等 Pacer 时钟。突发预算允许在 16KB 以内的数据立即发出，无需等待。这在连接刚建立、Pacer 尚未充分预热时尤其重要——否则第一个包就得等 next_send_time，白白浪费了空闲链路。

`CanSend` 的判断逻辑体现了这个折中：

```
pacing_rate == 0?  → 允许发送（Pacer 未激活）
burst_budget > 0?  → 允许发送（突发预算内）
now ≥ next_send_time?  → 允许发送（到了定时点）
否则  → 等待，返回 TimeUntilSend() 微秒
```

发包后，如果突发预算足够，扣减 budget 并允许立即继续发；否则根据 pacing rate 计算下次发送时间：`next_send_time = sent_time + bytes × 1000 / pacing_rate`。burst budget 按经过时间和 pacing rate 线性补充，上限为 `max_burst_bytes_`（16KB）。

Pacer 和拥塞控制的协作关系在 `ICongestionControl::CanSend()` 的三态返回值中被精确地编码：

```
调用 CanSend(now, &can_send_bytes):

返回 kOk            → 窗口有余量，Pacer 也允许 → 立即发送
返回 kBlockedByCwnd  → 管道满了 → 等 ACK 释放空间
返回 kBlockedByPacing → 管道有余量但节奏限速 → 等 next_send_time
```

发送路径同时尊重两把尺子——cwnd 控制总量上限，Pacer 控制发送节奏。两者缺一不可：只有 cwnd 没有 Pacer，突发打满缓冲区；只有 Pacer 没有 cwnd，总量失控导致持续排队。

为什么 BBR 比 Reno/Cubic 更依赖 Pacer？因为 Reno/Cubic 的主要控制手段是 cwnd——它们通过限制 inflight 总量间接控制速率，即使发送是突发的，只要总量不超过 cwnd，系统在统计上仍然稳定。但 BBR 的核心控制变量是 pacing rate——模型直接输出"应该以多快的速度发送"，Pacer 是这个输出的执行器。没有 Pacer 的 BBR 等于没有手的大脑——知道该做什么，但做不出来。

quicX 的设计选择是：**所有五种拥塞控制算法内部都持有 Pacer 实例。** 不存在"只有 BBR 需要 Pacer"的特殊路径。Reno 和 Cubic 的 pacing rate 由 cwnd / smoothed_rtt 推算，虽然精度不如 BBR 的模型输出，但匀速发送对它们同样有益——减少突发、减少 RTT 噪声、减少缓冲区瞬时溢出。

---

## 23.4 同一套底盘，跑不同算法：工厂装配、连接级选择与调优边界

接口定义了算法必须做什么，工厂决定了哪种算法被创建出来。quicX 的 `CongestionControlFactory`（位于 `src/quic/congestion_control/congestion_control_factory.h/.cpp`）通过枚举和 switch-case 完成这个映射：

```cpp
// quicX: src/quic/congestion_control/congestion_control_factory.h
enum class CongestionControlType {
    kCubic,
    kBbrV1,
    kBbrV2,
    kBbrV3,
    kReno
};
```

工厂的创建逻辑极其简洁：

```cpp
// quicX: src/quic/congestion_control/congestion_control_factory.cpp
std::unique_ptr<ICongestionControl> CongestionControlFactory::Create(
    CongestionControlType type) {
    switch (type) {
        case kCubic: return std::make_unique<CubicCongestionControl>();
        case kReno:  return std::make_unique<RenoCongestionControl>();
        case kBbrV1: return std::make_unique<BBRv1CongestionControl>();
        case kBbrV2: return std::make_unique<BBRv2CongestionControl>();
        case kBbrV3: return std::make_unique<BBRv3CongestionControl>();
        default:     return nullptr;
    }
}
```

这个设计的工程价值在于：新算法的接入路径被压缩到四步——实现 `ICongestionControl` 接口、添加枚举值、在 switch-case 中注册、编写测试。不需要修改连接层代码，不需要修改发送路径，不需要修改 Pacer。如果 BBR v4 或某个全新算法出现，接入成本是可预期的。

工厂创建出来的实例在使用前需要配置。`CcConfigV2` 定义了所有算法共享的参数边界：

```cpp
// quicX: src/quic/congestion_control/if_congestion_control.h
struct CcConfigV2 {
    uint64_t initial_cwnd_bytes = 10 * 1460;   // 初始窗口 ≈ 10 MSS
    uint64_t min_cwnd_bytes    = 2 * 1460;     // 最小窗口 ≈ 2 MSS
    uint64_t max_cwnd_bytes    = 1000 * 1460;  // 最大窗口 ≈ 1000 MSS
    uint64_t mss_bytes         = 1460;          // 最大报文段大小
    double   beta              = 0.5;           // 丢包时 cwnd 回退比例
    bool     ecn_enabled       = false;         // ECN 支持开关
};
```

这些参数中，有些是可以合理调整的，有些如果修改会破坏算法的正确性。理解这个边界是工程调优的前提：

```
参数                 可调性      调优建议
──────────────────────────────────────────────────────────
initial_cwnd_bytes   ✅ 可调     数据中心可增大到 20-30 MSS 加速慢启动
min_cwnd_bytes       ⚠️ 谨慎    低于 2 MSS 会导致 PTO 后无法发送探测包
max_cwnd_bytes       ✅ 可调     高 BDP 网络可增大，但要评估内存占用
mss_bytes            ⚠️ 谨慎    受路径 MTU 约束，不是可以自由设置的
beta                 ⚠️ 谨慎    Reno 的 0.5 有理论支撑（AIMD 收敛性证明）
ecn_enabled          ✅ 可调     取决于网络是否部署了 ECN 支持
```

与 `CcConfigV2` 的共享参数不同，BBR 的内部参数——pacing_gain 2.885（Startup）、增益循环 [5/4, 3/4, 1×6]（ProbeBW）、loss_threshold 0.02、beta_loss 0.9、beta_ecn 0.85——是算法收敛性的结构性常量。这些值经过 Google 在 B4 和 YouTube 的大规模验证，修改它们等于创造了一个未经验证的新算法，而不是"调优了 BBR"。Cubic 的 C = 0.4 和 beta_cubic = 0.7 同理——它们是 RFC 9438 标准化的协议常量，不是配置参数。

连接级选择的工程价值在于：同一个进程可以为不同连接使用不同算法。一个 CDN 节点同时服务视频流（BBR v3 可能更合适）和 API 请求（Cubic 足够），不需要运行两套协议栈。A/B 测试时，可以把 1% 的连接切换到新算法版本，观察行为差异，而不需要灰度发布整个服务。

---

## 23.5 不是写完就算数：simulator、benchmark 与验证体系

拥塞控制的 bug 有一种独特的危险形态：**不是 crash，而是行为偏移。** 算法在大多数网络条件下正常工作，但在某种特定的带宽-时延-丢包率组合下悄悄退化——吞吐量下降 20%、RTT 莫名上升、或者与 Cubic 共存时挤占了对方 70% 的带宽。这种退化不会触发任何断言或错误码，只有通过系统性的仿真和基准测试才能发现。

quicX 的验证体系分为四个层次。

**第一层：单元测试。** 每种算法都有独立的单元测试文件（`reno_congestion_control_test.cpp`、`cubic_congestion_control_test.cpp`、`bbr_v1_congestion_control_test.cpp`、`bbr_v2_congestion_control_test.cpp`、`bbr_v3_congestion_control_test.cpp`）。单元测试验证的是状态转换的正确性——慢启动退出时 ssthresh 是否正确设置、丢包后 cwnd 是否按 beta 回退、ProbeBW 的子状态切换是否符合预期。单元测试是必要的基线，但它们在理想化的输入序列上运行，无法覆盖真实网络的复杂性。

**第二层：算法验证测试。** `cc_algorithm_validation_test.cpp` 跨算法比较——在同样的网络条件下，Reno、Cubic、BBR v1/v2/v3 的行为是否各自符合预期。这一层能发现"某种算法在某个场景下行为异常"的问题。

**第三层：真实网络场景仿真。** 这是验证体系的核心。quicX 的 `NetworkSimulator`（位于 `test/congestion_control/network_simulator.h/.cpp`）支持 14 种预设网络场景：

```
场景              基础 RTT    抖动      丢包率    带宽       队列
──────────────────────────────────────────────────────────────
Ideal             10ms       0         0%       无限       —
LowLatency        20ms       ±2ms      0.1%     100Mbps    —
HighLatency       200ms      ±20ms     1%       10Mbps     —
MobileNetwork     100ms      ±30ms     2%       5Mbps      100包
LossyNetwork      50ms       ±10ms     5%       20Mbps     —
BufferBloat       30ms       ±5ms      0.1%     10Mbps     500包
Satellite         600ms      ±50ms     0.5%     50Mbps     —
Unstable          80ms       ±40ms     3%       8Mbps      150包
Enterprise        5ms        ±0.5ms    0.01%    1Gbps      1000包
Broadband         15ms       ±3ms      0.2%     100Mbps    500包
FiveG             20ms       ±5ms      0.5%     200Mbps    800包
LTE               50ms       ±15ms     1%       50Mbps     400包
WiFi              8ms        ±4ms      0.3%     300Mbps    600包
CrossContinent    150ms      ±10ms     0.3%     100Mbps    1500包
```

Simulator 还支持动态场景——`NetworkDegradation`（网络逐步恶化）、`NetworkImprovement`（网络逐步改善）、`FluctuatingNetwork`（网络反复波动）。动态场景能暴露算法在条件变化时的适应能力，这是静态场景测试无法覆盖的维度。

`cc_realistic_network_test.cpp` 在这些仿真场景上运行所有算法，`cc_bbr_detailed_test.cpp` 专门针对 BBR 三代执行精细化的状态验证——比如 ProbeBW 在 BufferBloat 场景下是否正确进入 DOWN 状态排空队列，ProbeRTT 在 Satellite 高延迟链路上是否造成不可接受的吞吐骤降。

`CCTestFramework`（位于 `test/congestion_control/cc_test_framework.h/.cpp`）为所有测试提供统一的驱动和指标采集：

```
采集指标包括：
  吞吐量（throughput_mbps）
  丢包率（packet_loss_rate）
  平均/最大/最小 cwnd
  平均 RTT
  慢启动持续时间
  恢复次数
  cwnd 增长率
  状态快照历史（time, cwnd, bytes_in_flight, ssthresh, in_slow_start, in_recovery, rtt）
```

状态快照历史是最有价值的诊断工具——它记录了算法在仿真运行过程中每个时间点的完整状态，出现异常行为时可以回放整个状态演变过程，定位偏差首次出现的精确时刻。

**第四层：性能基准测试。** `congestion_bench.cpp`（位于 `test/benchmarks/`）测量算法的计算开销——`OnPacketAcked` 和 `OnPacketLost` 在高频调用下的吞吐性能。拥塞控制的计算发生在每个 ACK 到达的关键路径上，如果单次计算耗时过长，会成为高吞吐场景下的性能瓶颈。Benchmark 回答的不是"算法对不对"，而是"算法快不快"。

Simulator 和 Benchmark 是互补的。Simulator 回答"算法行为是否符合预期"（功能正确性），Benchmark 回答"算法实现是否足够高效"（性能开销）。两者缺一不可——一个行为正确但每次 ACK 计算耗时 100μs 的 BBR v3 实现，在高吞吐场景下是不可用的；一个计算飞快但在 MobileNetwork 场景下吞吐量只有 Cubic 一半的实现，同样不可用。

拥塞控制验证最危险的失败模式是：**算法在所有单元测试中通过，但在某种特定网络条件组合下行为退化。** 这种退化通常只有在仿真的第三、第四层才能被发现。把验证体系当成实现的一部分——而不是实现完成后的附加品——是 quicX 拥塞控制工程的核心态度。

---

## 23.6 拥塞控制是一场没有终点的校准

拥塞控制的真正难点不在于理解任何一种模型。Reno 的 AIMD 可以在一张幻灯片上讲完，Cubic 的三次函数公式只有一行，BBR 的 BDP = BtlBw × RTprop 甚至更简洁。难的是五种算法在同一个进程里同时运行，每条连接独立选择，而它们对"什么是拥塞信号"的回答彼此矛盾——Reno 和 Cubic 认为丢包就是拥塞，BBR v1 认为丢包不是拥塞，BBR v3 认为丢包是校准信号但不是减速命令。一个库必须让这些互相矛盾的控制哲学各自运转、互不干扰，而 ICongestionControl 的六个方法恰好划出了这条边界：接口规定了"你必须回答哪些问题"，但从不规定"你用什么逻辑回答"。

Pacer 在这个结构中扮演了一个容易被低估的角色。没有 Pacer 的拥塞控制只完成了一半——cwnd 控制的是"允许发多少"，但不控制"什么时候发"。一个 cwnd = 100 MSS 的连接，如果在一个 RTT 的开头把 100 个包全部灌出去，和均匀分布在整个 RTT 里发出去，对网络的冲击完全不同。前者制造一个 100 MSS 的突发脉冲，后者是一条平滑的流。NormalPacer 的令牌桶模型——pacing_rate 决定填充速率，burst_budget 16 KB 容忍微突发，next_send_time 精确到微秒——把"总量正确"转化成了"节奏正确"。对于 BBR 这种直接输出 pacing_rate 的算法，Pacer 不是辅助组件，而是速率控制的执行主体。

拥塞控制也是"永远不会完成"的模块。BBR v3 的 IETF 草案仍在更新，低轨卫星链路的 RTT 抖动模式和地面网络截然不同，6G 毫米波的带宽波动幅度远超当前算法的假设范围。新的网络条件意味着新的算法，新的算法意味着 CongestionControlType 枚举里多一个值、工厂 switch-case 里多一个分支、NetworkSimulator 里多几种场景配置。这条扩展路径已经被走过五次（kReno、kCubic、kBbrV1、kBbrV2、kBbrV3），第六次不会需要改动任何已有算法的代码。连接现在既可靠又能控速——而另一场更精细的博弈已在等待：数据如何在多条流里有秩序地流动。
