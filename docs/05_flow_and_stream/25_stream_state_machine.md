# 25. 流的诞生与终结：发送与接收状态机

Stream 有了身份——ID 编码、方向、类型——但身份不等于生命。

一条流从被创建到数据传输完成到最终被回收，中间要经历哪些阶段？发送侧说"我发完了"和接收侧说"我收全了"，是同一件事吗？FIN、RESET_STREAM、STOP_SENDING 三个终止动作为什么不是同义词？这些问题指向 Stream 设计中最精密也最容易出错的部分：**状态机**。

---

## 25.1 为什么一条流也需要状态机：数据传输不是"写进去、读出来"那么简单

初次接触 QUIC Stream 的开发者很容易产生一个直觉：流不就是一根管道吗？一端写入，另一端读出，写完了关掉，有什么复杂的？

但真实的传输场景远不止"写入-读出"这么简单。考虑一个具体的场景：客户端在一条双向流上发送 HTTP 请求，服务器返回响应。

客户端发完请求体后发送 FIN——"我的数据到此为止了"。但此刻发送的数据可能还在网络上游荡，可能丢了包需要重传，客户端需要等待 ACK 确认所有数据（包括 FIN）都被服务器收到。在等待的过程中，客户端不能再发送新数据（因为 FIN 已经承诺"不会再有新数据了"），但必须继续响应重传请求。服务器那边呢？它可能收到了 FIN，知道请求数据不会再多了，但之前的某些包还没到（乱序），它需要等待所有数据补齐之后才能把完整的请求交给应用层。应用层处理完之后，这条流在接收侧才算真正结束。

这个场景至少暴露了三个边界：

第一，**"发完了"和"对端收到了"不是同一件事**。发送方发出 FIN 只是表达了一个意图，这个意图是否被对端确认，是另一个独立的事件。发送方在 FIN 被 ACK 之前，不能释放这条流的发送状态。

第二，**发送侧和接收侧看到的"流的状态"天然不同**。发送侧关心的是"我还欠对端什么"——数据有没有发完、FIN 有没有被确认。接收侧关心的是"我还在等对端什么"——数据有没有收全、FIN 有没有到、应用层有没有读完。同一条流，两端的关注点完全不同。

第三，**流可以被异常打断**。发送方可能在任何时候决定放弃这条流（发 RESET_STREAM），接收方也可能在任何时候告诉发送方"我不要了"（发 STOP_SENDING）。这些打断发生在流生命周期的任何阶段，每种打断方式都需要不同的处理逻辑。

如果没有状态机来定义每个阶段"可以做什么、不可以做什么、收到什么信号应该怎么反应"，双端对流的当前阶段的理解就会分裂。发送方以为流还活着在重传数据，接收方已经把它当作终止了——这种不一致会导致资源泄漏、数据损坏、协议违规。

RFC 9000 §3 给出的解法是：**发送侧和接收侧各自维护一台独立的状态机**。§3.1 定义了发送侧状态机（Sending Stream States），§3.2 定义了接收侧状态机（Receiving Stream States）。两台状态机各自独立演进，通过帧信号（STREAM、FIN、RESET_STREAM、STOP_SENDING）在两端之间同步关键事件。

为什么不用一台统一的状态机？因为发送和接收的关注点根本不对称。发送侧的终点是"对端确认了我的数据"，接收侧的终点是"应用层读完了数据"——这两件事发生在不同的时间点、由不同的参与者驱动。用一台状态机来表达两套不同的规则，只会让逻辑变得不可维护。

---

## 25.2 发送侧状态机：从 Ready 到 DataRecvd，或者被 Reset 打断

RFC 9000 §3.1 定义了发送侧的完整状态图。quicX 的 `StreamStateMachineSend` 把这张图直接翻译成了 C++ 代码，头文件注释里甚至保留了 RFC 的 ASCII art：

```
          o
          | Create Stream (Sending)
          | Peer Creates Bidirectional Stream
          v
      +-------+
      | Ready | Send RESET_STREAM
      |       |-----------------------.
      +-------+                       |
          |                           |
          | Send STREAM /             |
          | STREAM_DATA_BLOCKED       |
          v                           |
      +-------+                       |
      | Send  | Send RESET_STREAM     |
      |       |---------------------->|
      +-------+                       |
          |                           |
          | Send STREAM + FIN         |
          v                           v
      +-------+                   +-------+
      | Data  | Send RESET_STREAM | Reset |
      | Sent  |------------------>| Sent  |
      +-------+                   +-------+
          |                           |
          | Recv All ACKs             | Recv ACK
          v                           v
      +-------+                   +-------+
      | Data  |                   | Reset |
      | Recvd |                   | Recvd |
      +-------+                   +-------+
```

正常路径走左侧：**Ready → Send → DataSent → DataRecvd**。

**Ready** 是起点。流被创建后，发送侧进入 Ready 状态——"可以接收应用数据了，但还没发过任何东西"。Ready 状态给了应用层一个缓冲窗口：你可以先把数据写进来，QUIC 会选择合适的时机打包发送。

**Send** 是工作状态。当发送侧第一次发出 STREAM 帧（或 STREAM_DATA_BLOCKED 帧）时，流从 Ready 转入 Send。这意味着数据已经开始上路了。在 Send 状态下，发送侧持续发送 STREAM 帧，每一帧携带这条流上的一段数据及其偏移量。如果流控额度耗尽，发送侧可以发送 STREAM_DATA_BLOCKED 帧通知对端"我被卡住了"——但这不会改变状态，流仍然处于 Send。

**DataSent** 是等待确认的状态。当发送侧发出带 FIN 位的 STREAM 帧时——"我的数据到此为止了"——流转入 DataSent。这个状态表达了一个不可撤回的承诺：从现在起，发送侧不会再在这条流上发送任何新的字节。但承诺不等于完成——之前发出的数据可能丢包需要重传，FIN 本身也需要被对端 ACK。DataSent 状态下，发送侧不能发送新的 STREAM 帧或 STREAM_DATA_BLOCKED 帧（RFC 9000 §3.1 明确禁止），但必须继续响应重传。

**DataRecvd** 是发送侧的正常终态。当所有发送的数据（包括 FIN）都被对端 ACK 之后，流进入 DataRecvd——"我的传输任务彻底完成了"。到达这个状态后，发送侧状态机不需要再做任何事。

异常路径走右侧：任何阶段都可以转入 **ResetSent → ResetRecvd**。

发送侧在 Ready、Send 或 DataSent 三种状态下，都可以发送 RESET_STREAM 帧来放弃这条流。RESET_STREAM 的语义与 FIN 截然不同：FIN 说"我的数据发完了，你留着"，RESET_STREAM 说"我不发了，你把我之前发的数据都作废"。发送 RESET_STREAM 后流进入 ResetSent 状态，等待对端 ACK 确认，收到确认后进入 ResetRecvd 终态。

RFC 9000 §3.1 还规定了一条容易忽略的细节：处于 DataSent 状态的流仍然可以发送 RESET_STREAM。这意味着即使你已经 FIN 了（承诺数据完整），你仍然可以反悔——用 RESET 来撤销整个流。这在实践中用于处理应用层发现发送错误数据后的紧急取消。

quicX 的 `StreamStateMachineSend::CheckCanSendFrame()` 精确地实现了这些规则：终止态（DataRecvd、ResetRecvd）不能发任何帧；ResetSent 和 DataSent 不能发 STREAM 或 STREAM_DATA_BLOCKED 帧。所有"什么状态下能做什么"的判断都被封装在状态机内部，外部代码只需要调用 `CheckCanSendFrame()` 就能知道当前能不能发，不需要自己推演状态。

---

## 25.3 接收侧状态机：从 Recv 到 DataRead，或者收到 Reset

RFC 9000 §3.2 定义了接收侧状态图。它和发送侧形状相似，但每个状态关注的边界完全不同：

```
          o
          | Recv STREAM / STREAM_DATA_BLOCKED / RESET_STREAM
          | Create Bidirectional Stream (Sending)
          | Recv MAX_STREAM_DATA / STOP_SENDING (Bidirectional)
          | Create Higher-Numbered Stream
          v
      +-------+
      |  Recv | Recv RESET_STREAM
      |       |-----------------------.
      +-------+                       |
          |                           |
          | Recv STREAM + FIN         |
          v                           |
      +-------+                       |
      | Size  |  Recv RESET_STREAM    |
      | Known |---------------------->|
      +-------+                       |
          |                           |
          | Recv All Data             |
          v                           v
      +-------+ Recv RESET_STREAM +-------+
      | Data  |--- (optional) --->| Reset |
      | Recvd |                   | Recvd |
      +-------+                   +-------+
          |                           |
          | App Read All Data         | App Read RST
          v                           v
      +-------+                   +-------+
      | Data  |                   | Reset |
      | Read  |                   | Read  |
      +-------+                   +-------+
```

正常路径走左侧：**Recv → SizeKnown → DataRecvd → DataRead**。

**Recv** 是接收侧的工作状态。收到第一个 STREAM 帧（或通过隐式创建进入）后，接收侧开始积极接收数据。每收到一个 STREAM 帧，接收侧根据 Offset 把数据放到正确位置。如果 Offset 连续，数据立刻可以交付给应用层；如果中间有洞（丢包或乱序），先存入乱序缓存等待补齐。在 Recv 状态下，接收侧还可以发送 MAX_STREAM_DATA 帧来扩大流控窗口，给发送方更多额度。

**SizeKnown** 是一个发送侧没有的关键状态。当接收侧收到带 FIN 位的 STREAM 帧时，它就知道了这条流的最终大小——FIN 所在帧的 Offset + Length 就是数据的终点。从 Recv 到 SizeKnown 的转换，表达的是"我现在知道要等多少数据了"。但知道总量不等于已经收全——可能还有乱序数据在路上。SizeKnown 状态下接收侧继续接收迟到的 STREAM 帧（补齐乱序的洞），直到所有数据都收齐。

**DataRecvd** 意味着传输层面的接收完成。所有字节——从 Offset 0 到 FIN 位标记的终点——都已经到齐，放在接收缓冲区里等待应用层读取。

**DataRead** 是接收侧的正常终态。应用程序读完了接收缓冲区中的所有数据后，流进入 DataRead。这个状态标志着接收侧的生命周期彻底结束——传输层不再需要为这条流维护任何状态。

注意 DataRecvd 和 DataRead 的区别：DataRecvd 是"传输层收完了"，DataRead 是"应用层也读完了"。这两个时间点可能相隔很远——应用层可能很忙，迟迟不来读取数据。这个分离在发送侧不存在：发送侧不关心对端的应用层什么时候处理数据，它只关心自己的数据是否被 ACK。

异常路径走右侧。接收侧在 Recv 或 SizeKnown 状态下收到 RESET_STREAM 帧，进入 **ResetRecvd**；应用层被通知重置后进入 **ResetRead** 终态。

接收侧独有的一个武器是 **STOP_SENDING** 帧（RFC 9000 §3.5）。如果接收方不想要这条流上的数据了——比如 HTTP 请求已经被取消，或者接收端资源不足——它可以发送 STOP_SENDING 帧来请求发送方终止。注意措辞：是"请求"而非"命令"。STOP_SENDING 告诉发送方"你可以不用继续发了"，发送方收到后通常会回复 RESET_STREAM——但协议并不强制要求。STOP_SENDING 改变的是发送侧的行为，接收侧的状态机本身不因发送 STOP_SENDING 而转换。

quicX 的 `StreamStateMachineRecv::CheckCanSendFrame()` 体现了这个细节：STOP_SENDING 在非 Reset 状态下都可以发送，而 MAX_STREAM_DATA 只能在 Recv 和 SizeKnown 状态下发送——因为一旦数据收完了（DataRecvd），就没有必要再扩大窗口了。

---

## 25.4 三种终止不是同义词：FIN、RESET_STREAM、STOP_SENDING 各自表达什么

Stream 状态机最精密的地方不在"开始收发"，而在"如何结束"。三种终止动作经常被混为一谈，但它们的语义截然不同。

**FIN：发送方说"我说完了"。**

FIN 是 STREAM 帧上的一个标志位。发送方发送带 FIN 的 STREAM 帧，表达的是："从 Offset 0 到这个 FIN 帧标记的位置，就是我在这条流上发送的全部数据。"FIN 是一个**完整性承诺**——发送方保证数据到此为止，接收方可以安全地把收到的数据当作完整的消息来处理。

FIN 是单向的（只影响发送方向）、不可逆的（一旦 FIN 就不能再发新数据）、需要确认的（FIN 被 ACK 后发送侧才能进入终态）。在双向流上，一端 FIN 只关闭它自己的发送方向，对端仍然可以继续发送数据。

**RESET_STREAM：发送方说"我不说了，你把之前的都扔了吧"。**

RESET_STREAM 是一个独立的帧类型（RFC 9000 §19.4），携带三个关键信息：Stream ID、应用层错误码、以及这条流的最终大小（Final Size）。它表达的是："我决定放弃这条流的数据传输，你收到的数据都不算数了。"

RESET_STREAM 与 FIN 的核心区别在于**对已发数据的态度**：FIN 说"我的数据是完整的，你留着"；RESET_STREAM 说"我的数据不完整，你丢掉"。RESET_STREAM 可以在任何时候发送，包括 DataSent 状态——即使 FIN 已经发了，也可以用 RESET_STREAM 来撤销。

RESET_STREAM 携带 Final Size 有一个重要原因：接收方需要知道流的最终偏移量来正确维护连接级流控计数。即使数据被作废了，它消耗的流控额度仍然要被计入。

**STOP_SENDING：接收方说"你别发了，我不要了"。**

STOP_SENDING（RFC 9000 §3.5）是接收方发给发送方的请求。它不直接终止流——它请求发送方来终止。这种间接设计源于状态机的分权原则：流的发送侧只有发送方有权终止（通过 FIN 或 RESET_STREAM），接收方不能越俎代庖。

发送方收到 STOP_SENDING 后，通常的反应是发送 RESET_STREAM。这形成了一个互动序列：

```
接收方                              发送方
  |                                   |
  |--- STOP_SENDING (error_code) ---->|  "我不要了"
  |                                   |
  |<--- RESET_STREAM (final_size) ----|  "好，我不发了"
  |                                   |
```

RFC 9000 §3.5 特别指出：STOP_SENDING 只有在尚未收到 RESET_STREAM 的状态下才有意义——如果发送方已经 RESET 了，接收方再发 STOP_SENDING 没有任何效果。quicX 的实现也遵循了这一点：`CheckCanSendFrame(FrameType::kStopSending)` 在 ResetRecvd 和 ResetRead 状态下返回 false。

把三者放在一起对比：

| 维度 | FIN | RESET_STREAM | STOP_SENDING |
|------|-----|-------------|-------------|
| 谁发出 | 发送方 | 发送方 | 接收方 |
| 语义 | "我数据发完了" | "我不发了，数据作废" | "你别发了，我不要了" |
| 已发数据的命运 | 保留，完整交付 | 作废，接收方丢弃 | 取决于发送方是否响应 RESET |
| 对状态机的影响 | 发送侧 Send→DataSent | 发送侧→ResetSent | 不直接改变任何状态机 |
| 是否需要确认 | 需要（通过 ACK） | 需要（通过 ACK） | 不需要（它是请求不是状态变更） |

大多数 Stream 实现的 bug 都出在终止路径上——处理 FIN、RESET_STREAM 和 STOP_SENDING 交错到达时的边界条件，比处理正常数据传输要困难得多。

---

## 25.5 quicX 的双状态机：StreamStateMachineSend 与 StreamStateMachineRecv 如何落地

RFC 的状态图定义了规则，quicX 的工作是把这些规则翻译成可执行代码。这一节不逐函数解读源码，而是展示 quicX 如何把"两台独立状态机"这个设计原语落地为工程组件。

**第一层：StreamState 枚举——10 种状态值，用位标志编码。**

quicX 在 `type.h` 中用 `uint16_t` 定义了 StreamState 枚举：

```cpp
enum class StreamState: uint16_t {
    kUnknown     = 0,
    // sending stream states
    kReady       = 0x0001,
    kSend        = 0x0002,
    kDataSent    = 0x0004,
    kResetSent   = 0x0008,
    // receiving stream states
    kRecv        = 0x0010,
    kSizeKnown   = 0x0020,
    kDataRead    = 0x0040,
    kResetRead   = 0x0080,
    // common termination states
    kDataRecvd   = 0x0100,
    kResetRecvd  = 0x0200,
};
```

发送侧状态占 0x0001~0x0008，接收侧状态占 0x0010~0x0080，公共终止态占 0x0100~0x0200。用位标志而非连续整数有一个工程好处：可以用位运算快速做集合判断（例如"当前状态是否属于终止态"可以写成 `state_ & 0x0300`），但 quicX 当前的实现没有利用这一点——它用 `switch-case` 逐值匹配，更直观也更易调试。

**第二层：IStreamStateMachine 接口——两个核心方法。**

`if_state_machine.h` 定义了状态机的抽象接口，只有两个纯虚函数：

```cpp
class IStreamStateMachine {
public:
    // 处理收到（或发出）的帧，驱动状态转换
    virtual bool OnFrame(uint16_t frame_type) = 0;
    // 检查当前状态是否允许发送某种帧
    virtual bool CheckCanSendFrame(uint16_t frame_type) = 0;
    // 获取当前状态
    StreamState GetStatus() { return state_; }
protected:
    StreamState state_;
};
```

`OnFrame()` 是状态机的"输入端"——每当一个帧被发送或接收，调用它来推进状态。`CheckCanSendFrame()` 是状态机的"查询端"——在构建帧之前调用它来判断"现在能不能做这件事"。这个设计把"驱动状态"和"查询状态"分成了两个独立操作，外部代码不需要理解状态转换细节，只需要问"我能做什么"就够了。

**第三层：两个实现类——发送侧和接收侧各一台。**

`StreamStateMachineSend` 的 `OnFrame()` 实现是一个 switch-case，精确对应 RFC 9000 §3.1 的每条转换箭头：

```cpp
bool StreamStateMachineSend::OnFrame(uint16_t frame_type) {
    switch (state_) {
        case StreamState::kReady:
            if (StreamFrame::IsStreamFrame(frame_type)) {
                state_ = StreamState::kSend;
                if (frame_type & StreamFrameFlag::kFinFlag) {
                    state_ = StreamState::kDataSent;  // Ready直接跳到DataSent
                }
                return true;
            }
            // STREAM_DATA_BLOCKED也能把流从Ready推到Send
            if (frame_type == FrameType::kStreamDataBlocked) {
                state_ = StreamState::kSend;
                return true;
            }
            if (frame_type == FrameType::kResetStream) {
                state_ = StreamState::kResetSent;
                return true;
            }
            break;
        case StreamState::kSend:
            // STREAM + FIN → DataSent; RESET_STREAM → ResetSent
            ...
        case StreamState::kDataSent:
            // 只接受 RESET_STREAM → ResetSent
            ...
    }
    return false;
}
```

注意 kReady 状态下发送带 FIN 的 STREAM 帧时，状态不是先到 kSend 再到 kDataSent，而是**直接跳到 kDataSent**。这是因为如果一条流的全部数据在一帧内发完（数据很短），Ready → Send 这个中间态没有存在的必要——直接到"数据已全部发出"更准确。

发送侧状态机还有一个接口方法 `AllAckDone()`，用于所有 ACK 收齐后推进到终态：

```cpp
bool StreamStateMachineSend::AllAckDone() {
    switch (state_) {
        case StreamState::kDataSent:
            state_ = StreamState::kDataRecvd;   // 正常终态
            break;
        case StreamState::kResetSent:
            state_ = StreamState::kResetRecvd;  // Reset终态
            break;
        default:
            return false;  // 其他状态调用AllAckDone是错误
    }
    return true;
}
```

`StreamStateMachineRecv` 的实现对称但不镜像。它有两个发送侧没有的方法：

```cpp
// 所有数据收齐后调用
bool StreamStateMachineRecv::RecvAllData() {
    if (state_ == StreamState::kSizeKnown) {
        if (is_reset_received_) {
            state_ = StreamState::kResetRecvd;  // 收到过Reset，走Reset路径
        } else {
            state_ = StreamState::kDataRecvd;   // 正常路径
        }
        return true;
    }
    ...
}

// 应用层读完数据后调用
bool StreamStateMachineRecv::AppReadAllData() {
    if (state_ == StreamState::kDataRecvd)
        state_ = StreamState::kDataRead;    // 正常终态
    else if (state_ == StreamState::kResetRecvd)
        state_ = StreamState::kResetRead;   // Reset终态
    ...
}
```

`RecvAllData()` 处理从 SizeKnown 到终态的转换。这里有一个工程细节值得注意：接收侧用 `is_reset_received_` 标志位来记录"是否收到过 RESET_STREAM"。为什么需要这个标志？因为 RFC 9000 §3.2 允许 RESET_STREAM 和 STREAM+FIN 以任意顺序到达。如果先收到 FIN 进入 SizeKnown，再收到 RESET_STREAM，接收侧在 `RecvAllData()` 时需要知道该走正常路径还是 Reset 路径——`is_reset_received_` 就是这个记忆。

`AppReadAllData()` 体现了接收侧独有的"应用层交付"阶段——DataRecvd 到 DataRead 的转换由应用程序的读取动作驱动，不是由网络事件驱动。这是接收侧状态机比发送侧多一个状态的根本原因。

**第四层：Stream 类如何持有状态机。**

在第 24 章的继承体系中：`SendStream` 持有一个 `shared_ptr<StreamStateMachineSend>`，`RecvStream` 持有一个 `shared_ptr<StreamStateMachineRecv>`。当 `BidirectionStream` 通过菱形继承同时拥有 SendStream 和 RecvStream 时，它就自然地同时持有了两台状态机。

`BidirectionStream` 增加了一个关键方法 `CheckStreamClose()`：

```cpp
void BidirectionStream::CheckStreamClose() {
    bool send_terminal =
        (send_machine_->GetStatus() == StreamState::kDataRecvd ||
         send_machine_->GetStatus() == StreamState::kResetRecvd);
    bool recv_terminal =
        (recv_machine_->GetStatus() == StreamState::kDataRead ||
         recv_machine_->GetStatus() == StreamState::kResetRead);

    if (send_terminal && recv_terminal) {
        stream_close_cb_(stream_id_);  // 两台状态机都到达终态，流关闭
    }
}
```

这段代码是 RFC 9000 §3 的直接表达：**双向流只有在发送侧和接收侧都到达终止态时才算关闭**。发送侧的终止态是 DataRecvd 或 ResetRecvd（所有数据/Reset 被 ACK），接收侧的终止态是 DataRead 或 ResetRead（应用层已处理完）。两者是 AND 关系——任何一边没有完成，流就不能被回收。

`BidirectionStream::OnFrame()` 在处理完每个帧之后都会调用 `CheckStreamClose()`——无论是收到 STREAM 帧、RESET_STREAM 帧还是 STOP_SENDING 帧。这保证了流关闭判断不会遗漏任何触发点。

这套四层架构——枚举定义状态空间、接口定义操作契约、实现类翻译 RFC 规则、Stream 类持有状态机——把"两台独立状态机"这个协议设计原语，分解成了四个层次清晰、各司其职的工程组件。

---

## 25.6 流有了自己的命运，但命运并不完全由自己掌控

状态机回答了"一条流的内部生命规则"：Ready 到 DataRecvd/DataRead 的正常路径，RESET_STREAM 和 STOP_SENDING 的打断边界，双向流两台状态机都到终态才能关闭。

但状态机没有回答另一组问题。在 Send 状态下，如果流控额度为零，流虽然"活着"却无法推进——该怎么表达"我被卡住了"？在连接的 MAX_STREAMS 限制下，新流可能根本无法进入 Ready 状态——该怎么等待、怎么被唤醒？接收方扩大流控窗口后，怎么把"闸门打开了"这个信号传递给发送方？

这些由外部力量施加的限制——流控额度、背压信号、动态协商——构成了流生命的另一半规则。状态机定义了流"能怎样活"，流控和背压定义了流"被允许怎样活"。下一章进入这个主题。

---
