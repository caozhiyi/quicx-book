# 27. quicX 的 Stream 管理：从 pending 到 manager 的工程全景

协议规则画了一张蓝图：Stream 有四条设计原语、两台状态机、三层流控闸门和一套背压协商回路。但规则不会自己运行。谁来决定什么时候创建流？谁来管理上千条流的活跃状态？谁来在 MAX_STREAMS 到达时唤醒排队的请求？谁来在流结束后回收资源？

这些问题的答案汇聚到一个类：`StreamManager`。

---

## 27.1 协议规则画了蓝图，StreamManager 要盖房子

Stream 系统目前有三组独立的规则：原语定义（ID、类型、方向）、生命周期管理（双状态机）、外部约束（流控额度与背压协商）。这些规则分散在不同的组件里——`StreamStateMachineSend`/`Recv` 管状态转换，`SendFlowController`/`RecvFlowController` 管额度，`SendStream`/`RecvStream`/`BidirectionStream` 管数据读写。

缺少的是一个中枢——把所有组件组织起来的调度器。考虑几个具体场景：

应用层要创建一条新的双向流。这个请求需要检查 `SendFlowController` 的并发流数量额度，分配一个合法的 Stream ID，初始化状态机，设置流控初始额度，把流注册到查找表里。如果额度不够，请求还不能简单失败——它需要被排队，等 MAX_STREAMS 到达后自动重试。

发送路径需要构建 STREAM 帧。连接上可能同时有上千条流，但在任一时刻只有一部分流有数据要发。遍历全部流太浪费——需要一个活跃列表来定位"有事做的流"，对每条活跃流查询流控额度、检查状态机是否允许发送、编码帧写入缓冲区。

一条流的发送侧和接收侧都到达终态后，它的资源——状态机、缓冲区、流控计数器、在查找表里的条目——必须被清理。过早清理会导致迟到的帧找不到对应的流，过晚清理会让管理结构无限膨胀。

这些事情没有一个组件能独立完成。在 quicX 里，`StreamManager` 就是这个中枢。它的头文件声明了四组职责：

```cpp
class StreamManager {
public:
    // 流的创建
    std::shared_ptr<IStream> MakeStreamWithFlowControl(StreamDirection type);
    bool MakeStreamAsync(StreamDirection type, stream_creation_callback callback);
    void RetryPendingStreamRequests();

    // 流的查找与调度
    std::shared_ptr<IStream> FindStream(uint64_t stream_id);
    void MarkStreamActive(std::shared_ptr<IStream> stream);
    bool BuildStreamFrames(IFrameVisitor* visitor, uint8_t encrypto_level);

    // 流的关闭与回收
    void CloseStream(uint64_t stream_id);
    void ResetAllStreams(uint64_t error);

    // 远端流的接纳
    std::shared_ptr<IStream> CreateRemoteStream(uint32_t init_size, uint64_t stream_id, StreamDirection direction);
};
```

四组方法对应四个生命周期阶段：创建、调度、回收、异常。接下来逐一展开。

---

## 27.2 流的创建不总是成功的：MakeStream 与异步建流

`MakeStreamWithFlowControl()` 是应用层创建流的标准入口。它的第一步不是分配 ID，而是检查额度：

```cpp
std::shared_ptr<IStream> StreamManager::MakeStreamWithFlowControl(StreamDirection type) {
    std::shared_ptr<IFrame> blocked_frame;
    if (type == StreamDirection::kBidirectional) {
        uint64_t stream_id;
        if (!send_flow_controller_->CanCreateBidiStream(stream_id, blocked_frame)) {
            // 额度不足，通知连接层发送 STREAMS_BLOCKED
            if (blocked_frame) {
                event_sink_.OnFrameReady(blocked_frame);
            }
            return nullptr;
        }
    }
    // ... 单向流同理
    // 额度允许：创建流实体
    return MakeStream(init_size, stream_id, type);
}
```

关键路径是：先问 `SendFlowController`"还能不能创建"，不能就生成 `StreamsBlockedFrame` 通知对端，返回空指针——但不报错。

返回空指针给应用层带来一个问题：它怎么知道什么时候该重试？自己轮询？写定时器？这些方案都把复杂性推给了调用方。`MakeStreamAsync()` 提供了另一条路径：

```cpp
bool StreamManager::MakeStreamAsync(StreamDirection type, stream_creation_callback callback) {
    auto stream = MakeStreamWithFlowControl(type);
    if (stream) {
        callback(stream, 0);  // 立即成功
        return true;
    }
    // 额度不足：排队等待
    std::lock_guard<std::mutex> lock(pending_streams_mutex_);
    pending_stream_requests_.push({type, callback});
    return true;
}
```

请求被封装成 `PendingStreamRequest` 放入队列：

```cpp
struct PendingStreamRequest {
    StreamDirection type;
    stream_creation_callback callback;
};
std::queue<PendingStreamRequest> pending_stream_requests_;
```

排队不是失败，而是"把背压表达为可等待的系统状态"。当对端发来 MAX_STREAMS 帧扩大了并发上限，`SendFlowController` 更新额度后，连接层调用 `RetryPendingStreamRequests()`：

```cpp
void StreamManager::RetryPendingStreamRequests() {
    std::lock_guard<std::mutex> lock(pending_streams_mutex_);
    while (!pending_stream_requests_.empty()) {
        auto& request = pending_stream_requests_.front();
        auto stream = MakeStreamWithFlowControl(request.type);
        if (!stream) break;  // 额度又用完了，停止重试
        request.callback(stream, 0);
        pending_stream_requests_.pop();
    }
}
```

按 FIFO 顺序逐个重试，每成功一个就移出队列，额度再次耗尽就停下——剩余的请求继续等待下一次 MAX_STREAMS。

为什么不在 `MakeStreamWithFlowControl()` 失败时直接返回错误码？因为流控阻塞是一个**可恢复的临时状态**——对端只是暂时不允许更多流，等旧流关闭释放了管理资源，它就会扩大上限。如果因为一次阻塞就让调用方自己写重试逻辑，每个使用流的地方都要重复一套"创建→失败→定时重试→成功"的循环。`MakeStreamAsync()` 把这套复杂性封装进了协议栈，应用层只需要提供一个回调函数。

RFC 9000 §4.6 在这里提供了一个重要的行为指引："端点绝不能等待接收 STREAMS_BLOCKED 信号才通告额外的信用。这样做会导致对等方至少被阻塞一个完整的往返时间。" quicX 的 `RecvFlowController` 在第 26 章已经展示了如何在剩余流数不足 4 条时就主动发送 MAX_STREAMS——正是遵循这条指引。

---

## 27.3 上千条流如何被高效调度：双缓冲活跃列表与 BuildStreamFrames

一条 QUIC 连接上可能同时存在数百甚至数千条流。但在任一发送时刻，只有一部分流有数据要发——大多数流可能在等待应用层写入，或者在等待流控额度。如果发送路径每次都遍历全部流，绝大部分迭代都是浪费。

quicX 的解法是**活跃列表**：只有"有事做"的流才会被注册到列表中，发送路径只遍历这个列表。当一条流收到了应用层的写入、或者流控额度被释放，它通过回调把自己标记为活跃：

```cpp
void StreamManager::MarkStreamActive(std::shared_ptr<IStream> stream) {
    active_streams_.Add(stream);
}
```

但这引出了一个并发问题：发送路径正在遍历活跃列表的时候，新的流可能同时被标记为活跃——迭代器会失效。传统解法是加锁，但发送路径是热路径，锁的代价太高。

quicX 用了一个更轻量的方案：**双缓冲**（`DoubleBuffer<std::shared_ptr<IStream>>`）。内部维护两个 `unordered_set`——一个是"读缓冲区"，当前正在被遍历；另一个是"写缓冲区"，接受新的注册。遍历结束后交换角色：

```cpp
template <typename T>
class DoubleBuffer {
    void Add(const T& item) { GetWriteBuffer().insert(item); }

    void Swap() {
        // 将旧读缓冲区的残余合并到新读缓冲区，然后清空旧缓冲区
        if (current_is_buffer1_) {
            buffer2_.insert(buffer1_.begin(), buffer1_.end());
            buffer1_.clear();
            current_is_buffer1_ = false;
        } else {
            buffer1_.insert(buffer2_.begin(), buffer2_.end());
            buffer2_.clear();
            current_is_buffer1_ = true;
        }
    }
};
```

`Swap()` 不只是简单地切换指针——它先把旧读缓冲区中还没处理完的项合并到新读缓冲区，保证不会丢失活跃流。这个设计不需要线程安全（quicX 的发送路径是单线程的），纯粹是为了解决"迭代时新元素插入导致迭代器失效"的问题。

`BuildStreamFrames()` 是发送路径的核心调度方法：

```cpp
bool StreamManager::BuildStreamFrames(IFrameVisitor* visitor, uint8_t encrypto_level) {
    active_streams_.Swap();
    auto& streams = active_streams_.GetReadBuffer();

    bool all_blocked = true;
    for (auto& stream : streams) {
        // 加密级别过滤：crypto stream 可以在任何级别发送，
        // 应用流只能在 0-RTT 或 1-RTT 级别发送
        if (stream->GetStreamID() != 0 &&
            encrypto_level != kEncryption0RTT &&
            encrypto_level != kEncryption1RTT) {
            continue;
        }

        auto result = stream->TrySendData(visitor, encrypto_level);
        switch (result) {
            case TrySendResult::kSuccess:
                all_blocked = false;
                break;
            case TrySendResult::kFlowControlBlocked:
                break;  // 流控阻塞，跳过这条流
            case TrySendResult::kBreak:
                return true;  // 缓冲区满，停止
            case TrySendResult::kFailed:
                break;  // 发送失败，跳过
        }
    }
    return !all_blocked;
}
```

几个设计决策值得注意：

**加密级别过滤**。QUIC 的 crypto stream（ID=0）可以在任何加密级别发送——因为握手数据本身就是建立加密的前提。但应用层的 STREAM 帧只能在 0-RTT 或 1-RTT 级别发送。`BuildStreamFrames` 在遍历时直接跳过不匹配的流，不需要每条流自己检查。

**四种返回值**。`TrySendData()` 不是简单的成功/失败——`kFlowControlBlocked` 表示这条流被流控卡住了但其他流可能没问题，`kBreak` 表示缓冲区空间用完了应该立即停止。当所有流都返回 `kFlowControlBlocked` 时，方法返回 false，避免上层陷入"反复调用但永远发不出数据"的死循环。

**`IFrameVisitor` 模式**。`BuildStreamFrames` 不直接操作缓冲区——它把一个 `IFrameVisitor` 指针传给每条流，流通过 visitor 编码帧。`IFrameVisitor` 接口中 `GetLeftStreamDataSize()` 返回剩余可写字节数，`SetStreamDataSizeLimit()` 设定流控上限——流控约束通过 visitor 传递到编码层，而不是流自己去查询控制器。`FixBufferFrameVisitor` 是标准实现：它从线程局部的 `BlockPool` 分配固定大小缓冲区，编码时追踪每条流的 offset 和 FIN 标记，为后续的 ACK 处理提供 `StreamDataInfo`。

---

## 27.4 流的回收与连接级清理

流不是"状态到了终态就完了"。一条流在状态机到达 `DataRecvd`/`DataRead` 或 `ResetRecvd`/`ResetRead` 之后，还需要从 StreamManager 的管理结构中移除——否则流表会无限膨胀。

```cpp
void StreamManager::CloseStream(uint64_t stream_id) {
    auto iter = streams_map_.find(stream_id);
    if (iter == streams_map_.end()) return;

    streams_map_.erase(iter);
    event_sink_.OnStreamClosed(stream_id);
}
```

`CloseStream()` 做两件事：从 `streams_map_` 中移除流实体，通过 `IConnectionEventSink` 通知连接层"这条流已经关闭了"。连接层可以据此更新统计信息或释放关联资源。

回收的时机为什么重要？如果过早回收——流的状态机还没到终态，但管理结构已经把它删了——后续到达的帧（重传的 STREAM 帧、迟到的 ACK）在 `FindStream()` 中找不到对应的流，要么被丢弃要么触发错误处理。如果过晚回收——在长连接场景下流不断创建和销毁，`streams_map_` 会积累大量已终止但未清理的条目，查找性能退化。

quicX 的策略是：由流自身在双侧状态机都到达终态时通知 StreamManager 调用 `CloseStream()`。这避免了 StreamManager 主动轮询流状态的开销。

连接关闭时的批量清理则由 `ResetAllStreams()` 处理：

```cpp
void StreamManager::ResetAllStreams(uint64_t error) {
    for (auto& [id, stream] : streams_map_) {
        stream->Reset(error);
    }
    streams_map_.clear();
}
```

不需要等每条流单独走完状态机的终态流程——连接都要关了，直接给所有流发 Reset、清空整个流表。这是合理的粗暴：正常情况下连接不会频繁关闭，而关闭时的首要目标是快速释放资源，不是精细地推进每条流的状态转换。

`FindStream()` 是收到帧时的查找入口。连接层收到一个携带 Stream ID 的帧（STREAM、RESET_STREAM、STOP_SENDING、MAX_STREAM_DATA 等），需要快速定位对应的流。`streams_map_` 是一个 `unordered_map<uint64_t, shared_ptr<IStream>>`——哈希表，O(1) 查找。

```cpp
std::shared_ptr<IStream> StreamManager::FindStream(uint64_t stream_id) {
    auto iter = streams_map_.find(stream_id);
    if (iter == streams_map_.end()) return nullptr;
    return iter->second;
}
```

如果查找返回空——可能是对端创建了一条本端尚未见过的流。这时连接层调用 `CreateRemoteStream()` 来接纳远端发起的流，检查流 ID 是否合法、是否超过本端的 MAX_STREAMS 限制，然后创建流实体并注册到流表中。

---

## 27.5 三层组件如何协同：状态机、流控控制器、StreamManager 的协作关系

前四章分别讲了各个组件的内部逻辑。现在把它们拉到一张图上，看看在运行时它们如何协作。

**场景一：应用层创建流并发送数据。**

```
应用层                StreamManager            SendFlowController       Stream 实体
  |                       |                          |                      |
  |-- MakeStreamAsync --> |                          |                      |
  |                       |-- CanCreateBidiStream -->|                      |
  |                       |<-- OK, stream_id=4 ------|                      |
  |                       |                          |                      |
  |                       |-- MakeStream(id=4) ----------------------------->|
  |                       |                          |             [初始化状态机]
  |                       |                          |             [设置流控额度]
  |<-- callback(stream) --|                          |                      |
  |                       |                          |                      |
  |-- stream.Write(data)  |                          |                      |
  |                       |                          |         [MarkStreamActive]
  |                       |<--- active_streams_.Add --|                      |
```

**场景二：发送路径构建 STREAM 帧。**

```
连接发送路径          StreamManager           活跃流              FrameVisitor
  |                       |                    |                      |
  |-- BuildStreamFrames ->|                    |                      |
  |                       |-- Swap() --------->|                      |
  |                       |                    |                      |
  |                       |-- TrySendData ---->|                      |
  |                       |                    |-- CheckCanSendFrame  |
  |                       |                    |   (状态机检查)        |
  |                       |                    |                      |
  |                       |                    |-- GetLeftDataSize -->|
  |                       |                    |<-- 剩余可写字节 -----|
  |                       |                    |                      |
  |                       |                    |-- HandleFrame ------>|
  |                       |                    |              [编码STREAM帧]
  |                       |                    |              [追踪offset/fin]
  |                       |<-- kSuccess -------|                      |
```

**场景三：收到 MAX_STREAMS 帧后唤醒排队请求。**

```
连接接收路径          SendFlowController       StreamManager         等待队列
  |                       |                       |                    |
  |-- MaxStreamsFrame ---->|                       |                    |
  |                       |-- 更新 max_streams_ --|                    |
  |                       |                       |                    |
  |                       |   RetryPending------->|                    |
  |                       |                       |-- pop() ---------> |
  |                       |                       |                    |
  |                       |<- CanCreateBidiStream |                    |
  |                       |-- OK, stream_id=8 --->|                    |
  |                       |                       |-- callback(stream) |
  |                       |                       |                    |
  |                       |<- CanCreateBidiStream |                    |
  |                       |-- 额度不足 ---------->|                    |
  |                       |                       |-- break (停止重试) |
```

**场景四：流结束后的资源回收。**

```
Stream 实体           状态机                  StreamManager         连接层
  |                    |                          |                   |
  |-- 收到 FIN ACK --->|                          |                   |
  |                    |-- DataRecvd(终态) ------->|                   |
  |                    |                          |                   |
  |   [双侧都到终态]    |                          |                   |
  |                    |                          |                   |
  |------ CloseStream(stream_id) ---------------->|                   |
  |                                               |-- erase(map) --  |
  |                                               |-- OnStreamClosed->|
```

四个场景覆盖了流的完整生命周期。注意协作模式的一个共同特征：**每个组件只负责自己的判断，决策权分散**。SendFlowController 只回答"能不能创建/发送"，不关心创建的具体流程；状态机只回答"当前状态允不允许这个操作"，不关心流控额度；StreamManager 只负责调度和生命周期管理，不关心额度计算和状态转换的内部逻辑。组件之间通过方法调用传递判断结果，不共享内部状态。

这种分离让每个组件可以独立测试、独立演化。SendFlowController 的扩窗策略从"固定增量"改成"剩余不足10%就翻倍"，不影响 StreamManager 的任何代码；StreamManager 从单缓冲改成双缓冲，不影响流控控制器和状态机的任何逻辑。

---

## 27.6 Stream 系统的完整闭环

Stream 系统到此形成了完整闭环：设计原语给出身份（ID 编码、方向、类型），双状态机驱动生命周期，流控额度与背压协商施加外部约束，StreamManager 把这三组规则组织成一个协调运转的工程系统。

到这里，QUIC 的传输层已经完整——连接可靠、速率可控、数据可以在多条独立的流中有序流动、流的创建和销毁有高效的管理机制。但 Stream 系统只提供了传输原语：一条流可以独立传输有序字节，但这些字节代表什么——是 HTTP 请求？是控制信息？是头部压缩的编解码器状态？——需要上层协议来定义。

HTTP/3 正是建立在 QUIC Stream 之上的应用层协议。它把不同类型的 HTTP 语义映射到不同类型的 Stream 上——Request Stream 用双向流，Control Stream 和 QPACK Stream 用单向流。这个映射不是随意的，它的理由与本卷讲的 Stream 原语直接相关。

---
