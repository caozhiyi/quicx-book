# 18. 刺刀见红：异步定时器与连接生命周期的暗战

上一章把发送管线的最后一块拼图放好，可靠传输的协议闭环合上了——ACK 驱动丢包探测、丢包探测触发语义恢复、恢复路径把帧推进 `PacketBuilder`、`PacketBuilder` 把帧变成字节序列送上网络。在纸面上，每个齿轮咬合着下一个齿轮转动。

但第 17 章结尾留了一个缺口：竞态。定时器回调和数据到达交错执行、连接关闭和发送路径并发访问——这些问题只有在真正运行的系统里才会暴露。本章要做的，就是走进这个缺口。

本章分六节。18.1 先给出最经典的事故现场——PTO 回调触发时连接已经关闭。18.2 把问题从个案提升为系统性风险：异步回调为什么天然制造悬垂引用。18.3 聚焦卷三特有的竞态——关闭路径和重传路径迎面相撞。18.4 引出工程上的第一道闸门——`weak_ptr` 为什么不是编码风格，而是保命手段。18.5 落到 quicX 的实际实现，展示它如何用状态机、弱引用和析构清理三层防护把竞态压住。18.6 收束全卷：协议正确只是起点，系统能活着才是终点。

---

## 18.1 回调晚了一步，世界就变了：PTO timer 触发时连接未必还活着

PTO 在协议层面是一个简洁的装置：设一个定时器，时间到了检查有没有 ACK 没回来，如果有，就发一到两个探测包（RFC 9002 §6.2）。第 15 章已经讲过它的触发条件和计算公式，这里不再重复。问题在于：这个"时间到了"的回调，发生在和设置定时器完全不同的上下文里。

设置 PTO 定时器时，连接是活着的——发了一个包，启动计时，等待 ACK。但 PTO 回调什么时候执行，取决于事件循环的调度，不取决于协议的逻辑顺序。在 PTO 等待的这段时间里，任何事都可能发生：

```
  t=0ms    发出 Packet #42，设置 PTO = 300ms
  t=80ms   对端发来 CONNECTION_CLOSE
  t=85ms   连接状态 → Closing
  t=90ms   OnStateToClosing() 清理发送队列和重传记录
  t=300ms  PTO 回调触发——它还想检查 Packet #42 的 ACK
           但 sent_packets 已经被清空，Connection 正在析构
```

这就是最经典的事故现场。PTO 回调不知道世界已经变了。它按照"原定计划"去访问发送记录——但发送记录已经被 `ClearRetransmissionData()` 清空，连接对象可能正在析构或已经析构。如果回调函数持有的是裸指针或强引用，这一刻就是 segfault。

问题的根源不在 PTO 本身。RFC 9002 §6.2 定义的 PTO 逻辑假设了一个隐含前提：当 PTO 触发时，连接仍然处于活跃传输状态。但工程实现无法保证这个前提——因为定时器是中立的，它只关心"时间到了没有"，不关心"连接还活着没有"。

RFC 9000 §10.1 规定了连接关闭的 Closing 状态，§10.2 规定了 Draining 状态。这两个状态都意味着连接已经不再进行正常数据传输。但 PTO 定时器可能在连接进入这些状态之前就被设置好了，它的回调穿越了状态边界——从"活着"的世界跳到了"正在死去"的世界。

**定时器的中立视角和连接的实际生命周期之间，存在天然的时间裂缝。** 这道裂缝贯穿本章所有讨论。

---

## 18.2 异步系统最危险的不是延迟，而是悬垂：回调为什么特别容易制造野指针

PTO 的问题不是孤例。整个可靠传输路径面对的，是异步系统的一个根本性挑战：回调天然脱离原始调用栈。

在同步代码里，调用一个函数，函数执行完返回——调用栈是清晰的，前后关系是确定的。如果对象在函数执行期间被释放了，通常很容易发现，因为释放动作在调用栈里是可见的。但在异步系统里，你设置一个回调然后转身离开——回调什么时候执行，取决于事件循环，而不是你的代码。

TCP 也有 RTO 重传和连接关闭的竞态，但 TCP 的重传逻辑跑在内核态的同步调用栈里，定时器触发和连接关闭在同一个持有 `sock` 锁的上下文中串行执行——内核保证了在处理定时器回调时，连接结构体不会被并发释放。QUIC 不同。QUIC 跑在用户态，用异步事件循环驱动，定时器回调和连接关闭可能在同一个事件循环的不同迭代中交错执行。没有内核锁替你兜底，生命周期管理完全是你自己的事。

这就产生了一个问题：谁有资格活到回调发生？

Connection 对象可能还在内存里，但状态已经从 Connected 变成了 Closing。Stream 对象可能还在 map 里，但已经被 `RESET_STREAM` 标记为终结。发送记录可能还占着内存，但已经应该被清理。回调函数持有的引用指向的对象，物理上还活着，但逻辑上已经死了——或者更糟，物理上也已经死了。

在协议库里，use-after-free 比逻辑 bug 更致命。逻辑 bug 会导致功能异常——比如重传了一个不该重传的包——但系统还在跑。use-after-free 导致的是 segfault，进程直接崩溃，没有恢复机会，而且往往毫无征兆：上一秒代码还在正常运行，下一秒访问了一块已经被释放的内存。

真正的难点不是"怎么调回调"，而是"如何让回调感知到它依赖的对象是否还活着"。如果对象已经析构，回调应该优雅地退出，而不是继续访问一个空壳。这就是为什么 quicX 在可靠传输路径上大量使用弱引用和状态检查——它们不是编码风格偏好，而是活下去的必要条件。

---

## 18.3 两条路径迎面相撞：关闭路径与重传路径为什么最容易打架

前两节讲的是异步系统的一般性风险。这一节把问题拉回卷三的特定场景：关闭路径和重传路径的竞态。

RFC 9000 §10.1 规定，当连接需要关闭时，端点发送 `CONNECTION_CLOSE` 帧，进入 Closing 状态；§10.2 规定，收到对端 `CONNECTION_CLOSE` 的端点进入 Draining 状态。两种状态下，连接都不再进行正常数据传输。但 PTO 定时器可能在进入这些状态之前就已经被设置好了。

下面是一个具体的竞态时间线：

```
  ┌─── 关闭路径 ───────────────────┐   ┌─── 重传路径 ────────────────────┐
  │                                │   │                                │
  │ t=0   发出 Packet #55          │   │ t=0   设置 PTO = 250ms          │
  │ t=120 应用调用 Close()         │   │                                │
  │ t=121 CloseInternal()          │   │                                │
  │       ├─ ClearActiveStreams()   │   │                                │
  │       ├─ ClearRetransmissionData() │                                │
  │       │   └─ 清空 sent_packets │   │                                │
  │       │     + 取消所有 PTO timer│   │                                │
  │       └─ StartGracefulClose()  │   │                                │
  │ t=122 状态 → Closing           │   │                                │
  │ t=123 OnStateToClosing()       │   │                                │
  │       ├─ 发送 CONNECTION_CLOSE │   │                                │
  │       └─ 设置 closing timeout  │   │                                │
  │                                │   │ t=250 PTO 回调触发              │
  │                                │   │       └─ 想检查 Packet #55     │
  │                                │   │         但 sent_packets 已空   │
  └────────────────────────────────┘   └────────────────────────────────┘
```

两条路径都觉得自己有理。关闭路径说："连接要关了，发送记录必须清理，不能让悬挂的回调继续访问。"重传路径说："我等了 250ms，ACK 还没来，该重传了。"

如果 `ClearRetransmissionData()` 在 PTO 回调触发之前执行，它会取消所有待触发的 PTO timer——这是正常的关闭流程。但事件循环的调度不是确定性的。如果 PTO 回调恰好在 `ClearRetransmissionData()` 之前被放入了事件队列的就绪列表，那么它会在同一轮事件循环中被执行——此时发送记录可能正在被清理，或者已经被清理。

这种冲突在可靠传输模块尤其集中，因为这里的定时器最多、状态最复杂。PTO 定时器、Idle 超时定时器、Closing 超时定时器——每一个都可能和连接关闭路径产生竞态。

quicX 的做法是让关闭路径拥有更高的优先级。`ActiveSend()` 方法在执行任何发送操作之前，先检查 `IsTerminating()`：

```cpp
void BaseConnection::ActiveSend() {
    if (state_machine_.IsTerminating()) {
        return;  // 连接正在终止，放弃发送
    }
    if (active_connection_cb_) {
        active_connection_cb_(shared_from_this());
    }
}
```

`IsTerminating()` 覆盖了 Closing、Draining 和 Closed 三个状态。而 `TrySend()` 的守卫更精细——它允许 Closing 状态发送 `CONNECTION_CLOSE` 帧，但禁止 Draining 和 Closed 状态发送任何东西：

```cpp
bool BaseConnection::TrySend() {
    if (state_machine_.IsClosed() || state_machine_.IsDraining()) {
        return false;
    }
    // ... 继续正常发送逻辑 ...
}
```

这个区分是有意为之。RFC 9000 §10.1 规定 Closing 状态下端点可以重传 `CONNECTION_CLOSE` 帧来应对对端的重传包，但 Draining 状态下不能发送任何包。两个方法的守卫条件精确地反映了这个协议约束。

---

## 18.4 `weak_ptr` 不是优雅，是保命：生命周期隔离为什么必须明确

状态检查解决了"逻辑上已死"的问题：连接进入 Closing 后，所有发送操作被守卫条件拦住。但还有一个更根本的问题：如果连接对象本身已经被析构了呢？

状态检查的前提是：你还能访问到状态机。如果持有 Connection 的最后一个 `shared_ptr` 已经释放，Connection 对象已经析构，状态机也不存在了——这时候再调用 `state_machine_.IsTerminating()` 就是 use-after-free。

这就是 `weak_ptr` 解决的问题。它不是一种"更优雅的指针风格"，而是异步系统里的最低安全闸门：让回调能够感知"我依赖的对象是否还活着"。

模式很简单：回调持有 `weak_ptr` 而不是 `shared_ptr`，在执行之前调用 `lock()` 尝试获取强引用。如果对象已经析构，`lock()` 返回空——回调直接退出，不做任何事。如果对象还活着，`lock()` 返回的 `shared_ptr` 保证它在回调执行期间不会被析构。

quicX 中最典型的例子是 `UdpReceiver`。它维护了一张 fd → `IPacketReceiver` 的映射表，用于把收到的 UDP 包分发给正确的连接。但 `UdpReceiver` 的生命周期比单个连接长得多——连接可能随时关闭，而 `UdpReceiver` 继续运行。如果映射表持有 `shared_ptr<IPacketReceiver>`，那么连接对象会被映射表"续命"，无法正常析构。所以映射表持有的是 `weak_ptr`：

```cpp
// UdpReceiver 的映射表
std::unordered_map<int32_t, std::weak_ptr<IPacketReceiver>> receiver_map_;

// 分发包时的 lock() + check 模式
auto iter = receiver_map_.find(fd);
if (iter != receiver_map_.end()) {
    if (auto receiver = iter->second.lock()) {
        receiver->OnPacket(pkt);    // 对象还活着，安全调用
    } else {
        // 对象已析构，丢弃这个包
        Metrics::CounterInc(MetricsStd::UdpDroppedPackets);
    }
}
```

同样的模式出现在 `IWorker` 对 `IConnectionIDNotify` 的引用中——Worker 需要通知 Master 连接 ID 变更，但 Master 可能先于 Worker 析构，所以 Worker 持有的是 `weak_ptr<IConnectionIDNotify>`。全局资源 `GlobalResource` 中的 `thread_event_loop_` 也是 `weak_ptr<IEventLoop>`——因为 EventLoop 的生命周期由线程控制，其他模块不应该延长它的寿命。

`weak_ptr` 不是银弹。它解决的是"访问已析构对象"这一个特定问题，不解决"逻辑状态不一致"的问题。一个通过 `lock()` 获得的 Connection 对象，可能已经处于 Closing 状态——`weak_ptr` 保证它还活着，但不保证它还能做你想做的事。所以 `weak_ptr` 和状态检查是互补的两层防护：`weak_ptr` 保证物理上安全，状态检查保证逻辑上正确。

---

## 18.5 quicX 的收敛过程：从事故现场到稳定边界

理解了问题和工具，来看 quicX 是如何把这些防护组装成一套完整的生命周期控制体系的。

### 第一层：状态机收束

quicX 的 `ConnectionStateMachine` 定义了五个状态，形成严格的单向流转：

```
  Connecting ──→ Connected ──→ Closing ──→ Closed
                     │                       ↑
                     └──→ Draining ──────────┘
```

每个状态只能转到特定的其他状态。`OnClose()` 只允许从 Connecting 或 Connected 转到 Closing。`OnConnectionCloseFrameReceived()` 只允许转到 Draining（如果当前不在 Closed 或 Draining）。`OnCloseTimeout()` 只允许从 Closing 或 Draining 转到 Closed。任何不合法的转换都会被拒绝——状态机不会倒退，不会跳跃。

状态转换时，`SetState()` 会通过 `IConnectionStateListener` 回调通知 `BaseConnection`：

- `OnStateToClosing()`：清空发送队列和重传记录，发送 `CONNECTION_CLOSE` 帧，设置 closing 超时定时器
- `OnStateToDraining()`：清空发送队列和重传记录（但不发送任何帧），设置 draining 超时定时器
- `OnStateToClosed()`：停止 Idle 定时器，触发连接关闭回调

关键的一步发生在 `OnStateToClosing()` 和 `OnStateToDraining()` 中——它们调用 `ClearRetransmissionData()`，这个方法不仅清空 `sent_packets`，还会逐个取消所有待触发的 PTO 定时器：

```cpp
void SendControl::ClearRetransmissionData() {
    lost_packets_.clear();
    for (int i = 0; i < PacketNumberSpace::kNumberSpaceCount; i++) {
        for (auto& pair : unacked_packets_[i]) {
            timer_->RemoveTimer(pair.second.timer_task_);  // 逐个取消 PTO timer
        }
        unacked_packets_[i].clear();
    }
}
```

三个 Packet Number Space（Initial、Handshake、1-RTT）的所有未确认包记录被清空，对应的所有定时器被取消。这一步把重传路径从根上切断——不是等 PTO 回调触发后再检查状态，而是直接把 PTO 定时器从事件循环中移除。

### 第二层：发送守卫

即便有些回调在定时器被取消之前已经进入了事件队列的就绪列表，发送路径上的守卫条件仍然会拦住它们。quicX 有两层守卫：

- `ActiveSend()` 检查 `IsTerminating()`——Closing、Draining、Closed 三个状态下一律放弃
- `TrySend()` 检查 `IsClosed() || IsDraining()`——允许 Closing 状态发送 `CONNECTION_CLOSE` 的重传

这样即使一个 PTO 回调"逃过"了定时器取消，它触发的发送操作也会被守卫条件拦在门外。

### 第三层：析构安全

quicX 的第三层防护在析构函数中。`SendControl`、`ConnectionCloser`、`TimerCoordinator` 的析构函数都会主动取消自己注册的定时器并清空回调引用：

```
  ┌──────────────────────────────────────────────────────────┐
  │                   析构安全三件套                          │
  ├──────────────────────────────────────────────────────────┤
  │ SendControl::~SendControl()                              │
  │   ├── timer_->RemoveTimer(pto_timer_)    取消 PTO 定时器 │
  │   ├── stream_data_ack_cb_ = nullptr      清空 ACK 回调   │
  │   └── packet_lost_cb_ = nullptr          清空丢包回调    │
  ├──────────────────────────────────────────────────────────┤
  │ ConnectionCloser::~ConnectionCloser()                    │
  │   ├── event_loop_->RemoveTimer(graceful_close_timer_)    │
  │   └── connection_close_cb_ = nullptr     清空关闭回调    │
  ├──────────────────────────────────────────────────────────┤
  │ TimerCoordinator::~TimerCoordinator()                    │
  │   └── StopIdleTimer()                    停止 Idle 定时器│
  └──────────────────────────────────────────────────────────┘
```

这不是多余的防御。考虑这个场景：如果对象析构的顺序和预期不同——比如 `TimerCoordinator` 在 `SendControl` 之前析构——那么 `SendControl` 析构时尝试取消定时器仍然是安全的，因为它持有自己的 `timer_` 引用。每个组件负责清理自己注册的定时器，不依赖外部的清理顺序。

### 第四层：`shared_from_this` + `weak_ptr`

跨线程操作使用 `shared_from_this` 保证对象在回调执行期间不被析构：

```cpp
void BaseConnection::Close() {
    if (!event_loop_->IsInLoopThread()) {
        // 捕获 shared_ptr，保证 Connection 活到回调执行
        event_loop_->RunInLoop([self = shared_from_this()]() {
            self->CloseInternal();
        });
        return;
    }
    CloseInternal();
}
```

当应用线程调用 `Close()` 时，Connection 对象可能只被应用线程的 `shared_ptr` 持有。如果不捕获 `shared_from_this()`，应用线程释放 `shared_ptr` 后 Connection 会被析构，事件循环里排队的回调就变成了悬垂调用。`shared_from_this()` 让闭包也持有一个 `shared_ptr`，保证 Connection 至少活到回调执行完毕。

同样的模式出现在 `UdpReceiver` 的 `AddReceiver()` / `RemoveReceiver()`、`SendStream` 的 `Close()` / `Send()` / `Flush()` 等所有跨线程调用中。

而对于不应该延长对象寿命的场景——比如 `UdpReceiver` 的 `receiver_map_`、`IWorker` 对 `IConnectionIDNotify` 的引用——则使用 `weak_ptr`，通过 `lock()` + check 模式安全访问。

### 四层防护的协作

四层防护不是独立运行的，它们形成了纵深防御：

1. **状态机** 保证关闭流程的有序性——状态只能单向前进，不能倒退
2. **发送守卫** 拦住所有不应该发生的发送操作——即使有遗漏的回调
3. **析构清理** 在对象生命周期的最后一刻取消所有悬挂的定时器和回调
4. **智能指针** 保证跨线程回调的对象安全——`shared_from_this` 保活，`weak_ptr` 探测

任何单独一层都不完美。状态机不能阻止已经进入就绪队列的回调；发送守卫要求对象还活着才能检查；析构清理只是最后的保底。但四层叠加在一起，覆盖了从"逻辑死亡"到"物理析构"的全部时间窗口。

---

## 18.6 协议正确性只是起点：工程现场的暗战才是真正的考验

本章回答的核心问题是：为什么可靠传输相关的异步定时器和回调机制，天然容易与连接生命周期发生竞态冲突？

答案是：协议机制和工程实现之间存在时间维度的裂缝。RFC 9002 §6.2 定义的 PTO 假设"触发时连接还在传输"，RFC 9000 §10.1 定义的关闭流程假设"清理时没有并发回调"——但在异步事件循环里，这些假设随时可能被打破。定时器回调穿越状态边界，关闭路径和重传路径在同一个事件循环里交错执行，对象在回调还在排队时就被析构。

协议正确性是起点，不是终点。卷三从第 13 章"为什么 QUIC 要重做可靠性"讲起，经过 ACK 确认、丢包探测、语义重传、发送管线，建立了一套在纸面上严密的可靠传输闭环。但这套闭环要在真实系统里运转，还需要另一套完全不同的功夫——生命周期控制。状态机、发送守卫、析构清理、弱引用——这些不在 RFC 的任何一节里，却决定了协议实现是"能跑"还是"能活"。

当连接既能可靠传输、又不至于自己崩掉的时候，接下来才轮到一个新问题：如何跑得更快。
