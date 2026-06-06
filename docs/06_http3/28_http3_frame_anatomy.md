# 28. 换一张地图：HTTP/3 的帧体系与控制面

一条刚完成握手的 QUIC 连接能开出成百上千条流，每条流有自己的 ID、自己的偏移量、自己的额度窗口——但连接并不知道哪条流该放请求头、哪条流该放连接配置、哪条流该跑头部压缩的字典同步。流是通用容器，往里面装什么、怎么装、装错了怎么办，这些问题需要一份上层协议来回答。HTTP/3 就是这份协议。它不重新发明传输能力——流控、重传、多路复用都留给 QUIC——它只做一件事：**规定什么类型的数据走什么类型的流，以及流内部用什么格式的帧来标记语义边界**。

---

## 28.1 HTTP/2 的遗产与边界

HTTP/2 面对的世界只有一条 TCP 字节流。为了在这条单一字节流上跑出并发效果，HTTP/2 不得不在应用层自建一整套帧层：自己定义流 ID，自己做流控（WINDOW_UPDATE），自己做流重置（RST_STREAM），自己做优先级调度（PRIORITY），自己用 PING 探活。HTTP/2 的帧头是固定的 9 字节——3 字节长度、1 字节类型、1 字节标志、4 字节流标识符——十种帧类型（DATA、HEADERS、PRIORITY、RST_STREAM、SETTINGS、PUSH_PROMISE、PING、GOAWAY、WINDOW_UPDATE、CONTINUATION）覆盖了从数据搬运到连接管理的所有事情。

这套设计在 TCP 时代是合理的。TCP 只保证字节流可靠有序——它不知道"流"是什么，不知道"帧"是什么，更不知道应用层想要并发。HTTP/2 只能自力更生。

但 QUIC 改变了地基。QUIC 原生提供了流 ID（Stream ID 编码在包头里）、流控（MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS）、流重置（RESET_STREAM）、流终止请求（STOP_SENDING），优先级也被移出核心规范，改由 RFC 9218 Extensible Priorities 以扩展方式提供。HTTP/2 自建的那些传输层能力，QUIC 层已经具备。

HTTP/3 做的事情不是"把 HTTP/2 搬到 QUIC 上"，而是**职责重新划分**。凡是传输层能做的，HTTP/3 不再重做：

- 流控 → QUIC 层的 MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS（卷五）
- 流重置 → QUIC 层的 RESET_STREAM（第 25 章）
- 连接级 PING → QUIC 层的 PING 帧（第 6 章）
- 优先级 → RFC 9218 Extensible Priorities（扩展，不在 HTTP/3 核心规范里）
- CONTINUATION → HTTP/3 取消了这种帧——QUIC Stream 本身就保证有序交付，不再需要把头部块拆分成多个帧

HTTP/3 只保留应用层必须处理的事情：数据搬运（DATA）、头部搬运（HEADERS）、连接配置（SETTINGS）、优雅关闭（GOAWAY）、推送承诺（PUSH_PROMISE / CANCEL_PUSH / MAX_PUSH_ID）。帧从 HTTP/2 的十种缩减到七种，帧头从固定 9 字节改为变长整数编码（Type 和 Length 都是变长整数），更紧凑也更灵活。

这种精简不是"功能退化"。HTTP/3 能用更少的帧类型做同样的事情，恰恰是因为 QUIC 在传输层已经把脏活累活干完了。理解这个职责划分，是理解 HTTP/3 帧体系的前提。

---

## 28.2 五类专用流的分工

HTTP/2 的所有帧跑在同一条 TCP 连接上，靠帧头里的流标识符区分归属。HTTP/3 面对的是 QUIC 提供的多条独立流——问题变成了：HTTP/3 怎样把不同职责的数据安放到不同类型的流上？

答案是五类专用流，每类流承担一个明确的职责。

**Control Stream（控制流，类型 0x00）**。每个方向恰好一条，用单向流承载，不能关闭。RFC 9114 §6.2.1 要求每个端点在连接建立时必须发起一条控制流，控制流上传输的是连接级帧——SETTINGS、GOAWAY、MAX_PUSH_ID。控制流之所以用单向流而不是双向流，是为了让任一端点都能在准备好的第一时间发送控制帧，不需要等对端先开口（这在 0-RTT 场景下尤为重要）。

**Request Stream（请求流）**。双向流，承载一次 HTTP 请求/响应交互。客户端发起双向流，发送 HEADERS + DATA 表达请求，服务端在同一条流上回送 HEADERS + DATA 表达响应。一条请求流对应一次完整的 HTTP 语义交换。

**Push Stream（推送流，类型 0x01）**。单向流，由服务端发起，承载服务器主动推送的响应。推送流的头部除了流类型字节外，还包含一个 Push ID，用于关联此前在请求流上发出的 PUSH_PROMISE 帧。RFC 9114 明确规定：客户端不能发起推送流，服务端收到客户端的推送流必须报 `H3_STREAM_CREATION_ERROR`。

**QPACK Encoder Stream（类型 0x02）**。单向流，传输 QPACK 编码器指令——动态表插入、动态表容量更新。编码器指令必须独立传输，不能和请求数据混在一起，否则一条慢请求会阻塞所有后续请求的头部解码。

**QPACK Decoder Stream（类型 0x03）**。单向流，传输 QPACK 解码器反馈——Section Acknowledgement、Stream Cancellation、Insert Count Increment。这些反馈让编码器知道对端已经处理了哪些动态表条目，可以安全地淘汰旧条目或引用新条目。

五类流的分工不是偶然的设计，而是为了隔离不同性质的数据：

控制面和数据面分离——SETTINGS 和 GOAWAY 走控制流，请求数据走请求流。如果控制帧和请求数据混在同一条流上，一个大响应体的传输会延迟 GOAWAY 的送达，优雅关闭就不优雅了。

QPACK 指令独立传输——编码器和解码器各有专属流。QPACK 的动态表更新需要及时到达，如果和请求数据共享流，慢请求会阻塞动态表同步，导致后续请求的头部无法解码。

推送流有独立生命周期——推送响应可能在客户端发起请求之前就到达，也可能被客户端通过 CANCEL_PUSH 取消。独立的流让推送和请求的生命周期解耦。

在 quicX 中，流类型发现通过 `UnidentifiedStream` 实现。当 QUIC 层上报一条新的单向流时，HTTP/3 层不知道它是什么类型——流类型字节是单向流的第一个字节，需要读取后才能判断。quicX 的做法是先创建一个 `UnidentifiedStream` 包装这条原始流，注册 `OnData` 回调等待数据到达。数据到达后，从 buffer 中读取一个变长整数作为流类型，然后通过 `StreamTypeCallback` 把流类型、底层 QUIC 流和剩余数据一起传递给 Connection 层。Connection 层根据类型创建具体的流对象（`ControlReceiverStream`、`QpackEncoderReceiverStream` 等），并把剩余数据 feed 给新创建的流。

```cpp
// UnidentifiedStream::OnData —— 流类型发现的核心逻辑
void UnidentifiedStream::OnData(std::shared_ptr<IBufferRead> data,
                                 bool is_last, uint32_t error) {
    if (type_identified_) return;
    
    BufferDecodeWrapper wrapper(data);
    uint64_t stream_type = 0;
    if (!wrapper.DecodeVarint(stream_type)) return;  // 数据不足，等下次
    
    type_identified_ = true;
    stream_->SetStreamReadCallBack(nullptr);          // 注销回调
    type_callback_(stream_type, stream_, data);       // 交给 Connection 层分发
}
```

这个"先收一个字节再分发"的设计，让 Connection 层不需要预先知道对端会开什么类型的流，也不需要为每种流类型预留特殊的流 ID 范围——流类型完全由流内容的第一个字节自描述。

---

## 28.3 HTTP/3 帧体系整体轮廓

HTTP/3 的帧有统一的格式，RFC 9114 §7.1 定义如下：

```
HTTP/3 Frame {
  Type  (variable-length integer),
  Length (variable-length integer),
  Frame Payload (..),
}
```

Type 和 Length 都使用 QUIC 的变长整数编码（1/2/4/8 字节），而不是 HTTP/2 的固定字节数。这意味着绝大多数帧的头部只需要 2 字节（Type 1 字节 + Length 1 字节），比 HTTP/2 的 9 字节固定帧头紧凑得多。

七种帧各有职责，下表列出它们的类型值、功能定位和允许出现的流：

| 帧类型 | 类型值 | 功能 | 允许出现的流 |
|--------|--------|------|-------------|
| DATA | 0x00 | 承载 HTTP 消息体 | Request Stream, Push Stream |
| HEADERS | 0x01 | 承载 QPACK 编码的头部字段 | Request Stream, Push Stream |
| CANCEL_PUSH | 0x03 | 取消一个尚未开始的推送 | Control Stream |
| SETTINGS | 0x04 | 连接级配置协商 | Control Stream（且必须是首帧） |
| PUSH_PROMISE | 0x05 | 服务端预告将推送的请求头 | Request Stream |
| GOAWAY | 0x07 | 优雅关闭信号 | Control Stream |
| MAX_PUSH_ID | 0x0D | 客户端设置服务端可用的最大 Push ID | Control Stream |

帧和流的对应关系不是随意的。DATA 和 HEADERS 只出现在请求流和推送流上——它们承载 HTTP 消息，自然要跟着请求走。SETTINGS、GOAWAY、MAX_PUSH_ID、CANCEL_PUSH 只出现在控制流上——它们是连接级的管理动作，不属于任何一次请求。PUSH_PROMISE 比较特殊：它出现在请求流上（因为推送总是关联到某个请求），但它预告的推送响应会在独立的推送流上到达。

在错误类型的流上收到帧，RFC 9114 要求报 `H3_FRAME_UNEXPECTED` 连接错误。比如在控制流上收到 DATA 帧、在请求流上收到 SETTINGS 帧，都必须关闭连接。

帧载荷的长度必须与帧定义严格匹配——多了或少了字节都是 `H3_FRAME_ERROR`。收到未知类型的帧，RFC 9114 §7.2.8 要求**忽略**（读取 Length 字节后跳过），而不是报错。这个设计为协议扩展预留了空间。

quicX 的帧解析架构围绕 `IFrame` 接口和 `FrameDecoder` 调度器构建。`IFrame` 定义了四个纯虚方法：

```cpp
class IFrame {
public:
    virtual bool Encode(std::shared_ptr<IBuffer> buffer) = 0;
    virtual DecodeResult Decode(std::shared_ptr<IBuffer> buffer,
                                 bool with_type = false) = 0;
    virtual uint32_t EvaluateEncodeSize() = 0;
    virtual uint32_t EvaluatePayloadSize() = 0;
};
```

`FrameDecoder` 是一个状态机驱动的增量解码器，内部维护三种状态：

1. **ReadingFrameType**：从 buffer 读取一个变长整数作为帧类型
2. **DecodingFrame**：根据帧类型从工厂映射表创建具体帧对象，调用其 `Decode()` 方法
3. **SkippingUnknownFrame**：遇到未知类型时，读取 Length 后逐段跳过 payload 字节

"增量"意味着 `FrameDecoder` 支持跨多次调用的部分帧解码。当数据不足时（`DecodeResult::kNeedMoreData`），解码器保存当前状态和未完成的帧对象，等下一次数据到达后继续。这对流式传输至关重要——网络随时可能只送来帧的一部分。

对于未知帧类型的处理体现了 RFC 9114 §7.2.8 的要求：`FrameDecoder` 在 `kFrameCreatorMap` 中找不到对应的帧类型时，进入 `kSkippingUnknownFrame` 状态，先读取 Length varint，然后逐步跳过 payload 字节，跳过完毕后回到 `kReadingFrameType` 状态，继续处理下一帧。

七种帧在 quicX 中各有对应的类。以 `DataFrame` 为例，它持有 `length_` 和一个指向 payload buffer 的共享指针 `data_`。payload 不是值拷贝而是引用共享——这让 DATA 帧的编解码走的是零拷贝路径，与卷一第 2 章设计的 `IBuffer` 体系一脉相承。`HeadersFrame` 的设计类似，但它持有的 `encoded_fields_` 是 QPACK 编码后的头部字段块——帧本身不做头部解析，只负责搬运字节，解码留给 QPACK 层（第 30 章）。

---

## 28.4 控制流机制：SETTINGS 帧与 Transport Parameter 的职责边界

HTTP/3 连接的控制面运行在一对控制流上——客户端开一条，服务端开一条，都是单向流。RFC 9114 §6.2.1 对控制流有三条硬性要求：

1. 每个端点必须在连接建立时发起一条控制流
2. 控制流上发送的第一个帧必须是 SETTINGS——如果不是，接收端报 `H3_MISSING_SETTINGS` 连接错误
3. 控制流不能被关闭——关闭控制流是 `H3_CLOSED_CRITICAL_STREAM` 错误

SETTINGS 帧的载荷是一组 `(Identifier, Value)` 变长整数对，表达连接级的应用层配置。RFC 9114 §7.2.4 定义了以下参数：

| 参数 | Identifier | 含义 |
|------|-----------|------|
| QPACK_MAX_TABLE_CAPACITY | 0x01 | QPACK 动态表的最大容量（字节） |
| MAX_FIELD_SECTION_SIZE | 0x06 | 接受的头部字段区域最大大小 |
| QPACK_BLOCKED_STREAMS | 0x07 | 允许的 QPACK 阻塞流数量上限 |
| ENABLE_CONNECT_PROTOCOL | 0x08 | 是否启用 Extended CONNECT 协议 |

注意 Identifier 0x02 到 0x05 是保留值——它们曾在 HTTP/2 中使用（ENABLE_PUSH、MAX_CONCURRENT_STREAMS、INITIAL_WINDOW_SIZE、MAX_FRAME_SIZE），在 HTTP/3 中被禁止。收到这些 ID 必须报 `H3_SETTINGS_ERROR`。这不是偶然的遗漏，而是刻意的边界划分：并发流数量由 QUIC 层的 `MAX_STREAMS` 管理，流控窗口由 QUIC 层的 `MAX_STREAM_DATA` 管理，帧大小上限在变长编码下不再需要——HTTP/2 的这些"传输层关切"在 HTTP/3 里已经下沉到 QUIC 层。

这引出一个核心问题：QUIC 握手时已经通过 Transport Parameter 协商了一轮能力（最大空闲超时、初始流控窗口、最大 UDP payload 大小、ACK 延迟指数等），为什么 HTTP/3 还要再协商一轮？

答案是**层次隔离**。Transport Parameter 嵌入在 TLS 握手的 ClientHello / EncryptedExtensions 里，在 1-RTT 内就生效——但它协商的是传输层的事情。QUIC 层不应该知道 QPACK 的存在，不应该知道 HTTP 头部有大小限制，不应该知道 Extended CONNECT 是什么。反过来，HTTP/3 层不应该去管流控窗口多大、ACK 延迟多少。两层协商各管各的领域，互不越界。

在时序上，Transport Parameter 在握手期间交换（0-RTT 或 1-RTT），SETTINGS 在 HTTP/3 控制流建立后交换（可能更晚）。RFC 9114 允许端点在等待对端 SETTINGS 到达之前，使用默认值发送消息。在 0-RTT 场景下，客户端使用上一会话存储的 SETTINGS 值，服务器在接受 0-RTT 时不得发送比上次更严格的限制。

quicX 中 SETTINGS 的传播路径：

**发送端**。以客户端为例，`ClientConnection` 构造时创建一条单向发送流并初始化为 `ControlClientSenderStream`。初始化函数立即调用 `SendSettings()`——构造 `SettingsFrame` 对象，将 `Http3Settings` 中的参数编码为 `(Identifier, Value)` 对，写入发送 buffer。在调用 `SendSettings()` 之前，`EnsureStreamPreamble()` 已经把控制流的类型字节 0x00 写入流的首部，满足 RFC 9114 §6.2 对单向流首字节必须是流类型的要求。

**接收端**。`ControlReceiverStream` 在收到数据后，调用内部的 `FrameDecoder` 解码帧。`HandleFrame()` 方法执行首帧校验——如果 `settings_received_` 为 false 且收到的不是 SETTINGS 帧，立即返回 `H3_MISSING_SETTINGS` 错误。SETTINGS 帧解码成功后，通过 `settings_handler_` 回调传递给 Connection 层。Connection 层的 `HandleSettings()` 方法合并对端的 settings，同时校验是否包含 HTTP/2 遗留的保留 ID（0x02-0x05），如有则关闭连接。QPACK 相关的参数（`QPACK_MAX_TABLE_CAPACITY`、`QPACK_BLOCKED_STREAMS`）随后传递给 QPACK 编码器，初始化动态表容量和阻塞上限。

`SettingsFrame` 的编解码实现朴素而高效：`settings_` 用 `std::unordered_map<uint16_t, uint64_t>` 存储所有参数对。`Encode()` 先写入帧类型和 payload 长度（惰性计算），然后遍历 map 逐对写入 varint。`Decode()` 先读取 payload 长度，然后在长度范围内循环读取 `(id, value)` 对。如果数据不足，调用 `CancelDecode()` 回退读指针，返回 `kNeedMoreData`，等下次数据到达后继续。

---

## 28.5 GOAWAY 与优雅关闭

服务端需要升级代码、负载均衡器需要排空后端、连接空闲太久需要回收——这些场景都需要一种"温和告别"机制：不是突然断开连接，而是告诉对端"我不再接受新请求了，但现有的请求你放心，我会处理完"。GOAWAY 帧就是 HTTP/3 的这个机制。

GOAWAY 帧只出现在控制流上，载荷只有一个变长整数——但这个整数的含义因方向不同而异：

- **服务端 → 客户端**：这个整数是一个 Stream ID。含义是"所有 Stream ID 大于或等于这个值的请求，我不会处理"。客户端可以在收到 GOAWAY 后安全地在新连接上重试这些未处理的请求。
- **客户端 → 服务端**：这个整数是一个 Push ID。含义是"所有 Push ID 大于或等于这个值的推送，我不会接受"。

优雅关闭的流程分四步：

1. 发送方在控制流上发出 GOAWAY 帧，带上最后一个将处理的标识符
2. 接收方收到 GOAWAY 后，停止在这条连接上发起新的请求或推送
3. 已发起且标识符小于 GOAWAY 值的请求继续正常完成
4. 所有进行中的请求完成后，连接最终关闭

RFC 9114 §5.2 允许发送多个 GOAWAY 帧——比如服务端可以先发一个 GOAWAY(100) 表示"Stream ID 100 及以上的不处理了"，稍后在资源更紧张时再发一个 GOAWAY(50) 进一步收紧。但标识符只能递减，不能递增——如果后发的 GOAWAY 的标识符比先发的大，接收端必须报 `H3_ID_ERROR` 关闭连接。

GOAWAY 和 QUIC 层的 CONNECTION_CLOSE 是两个层次的事情。GOAWAY 是 HTTP/3 应用层的"预告"——它告诉对端"准备撤退"，但连接还活着，已有的请求还在跑。CONNECTION_CLOSE 是 QUIC 传输层的"执行"——它直接终结连接，所有流立即终止。正常的优雅关闭流程是：先发 GOAWAY，等所有进行中的请求完成，然后再发 CONNECTION_CLOSE 关闭底层连接。

quicX 中的实现：

`GoawayFrame` 是所有帧中最简单的——只有一个 `stream_id_` 字段（变长整数），`Encode()` 和 `Decode()` 各几行代码。

**发送 GOAWAY**。`ControlSenderStream::SendGoaway()` 构造 `GoawayFrame`，设置 stream ID，调用 `Encode()` 写入发送 buffer 后 flush。

**接收 GOAWAY**。`ControlReceiverStream` 的 `HandleFrame()` 在解码出 GOAWAY 帧后，通过 `goaway_handler_` 回调传递给 Connection 层。服务端的 `ControlServerReceiverStream` 额外维护了 `last_goaway_id_`：每次收到 GOAWAY 时校验新的 stream ID 不大于上一次的值，违反则报 `H3_ID_ERROR`——这就是 RFC 9114 §5.2 对 GOAWAY 标识符单调递减的强制要求。

Connection 层收到 GOAWAY 后的行为：客户端停止发起新请求（`ClientConnection::HandleGoaway()` 更新 goaway 标识符），服务端停止发起新推送（`ServerConnection::HandleGoaway()` 更新 push ID 上限）。已经在途的请求不受影响，继续正常处理。

---

## 28.6 quicX 如何把 HTTP/3 层架在 QUIC Stream 之上

前五节讲的是 HTTP/3 协议规范——帧格式、流分类、SETTINGS、GOAWAY。这一节转向工程：quicX 的 HTTP/3 层如何组织代码，把这些协议机制落地为可运行的系统。

quicX 的 HTTP/3 层分为四个子目录：

- `frame/`：七种帧的编解码和帧调度器
- `stream/`：五类流的发送端和接收端实现
- `connection/`：HTTP/3 连接管理（客户端和服务端）
- `qpack/`：头部压缩引擎（第 30 章展开）

**连接层是入口**。`IConnection` 基类定义了 HTTP/3 连接的生命周期：`Init()` 负责创建控制流和 QPACK 流并发送 SETTINGS；`HandleStream()` 在 QUIC 层上报新流时触发，由子类实现；`HandleSettings()` 处理对端的 SETTINGS 帧；`Close()` 关闭连接。`ClientConnection` 和 `ServerConnection` 分别实现客户端和服务端的逻辑。

**初始化时创建五类流**。以客户端为例，`ClientConnection` 的构造函数完成以下工作：

1. 创建一条单向发送流 → 初始化为 `ControlClientSenderStream`
2. 通过控制流发送 SETTINGS 帧
3. 如果启用推送，发送 `MAX_PUSH_ID` 帧
4. 创建 QPACK Encoder 和 Decoder 的发送流

服务端类似，但使用的是 `ControlSenderStream`（基类，不发 MAX_PUSH_ID）和 `ControlServerReceiverStream`（额外处理 MAX_PUSH_ID 和 CANCEL_PUSH）。

**流的发现与分发**。当 QUIC 层上报一条新的单向流时，Connection 层的处理流程是：

```
QUIC 上报新流 → 创建 UnidentifiedStream
                     ↓ OnData 回调
              读取流类型字节（varint）
                     ↓ StreamTypeCallback
              Connection::OnStreamTypeIdentified()
                     ↓ 根据类型分发
    ┌────────────────┼────────────────────────┐
    ↓                ↓                        ↓
ControlReceiverStream  QpackEncoderReceiverStream  PushReceiverStream
                       QpackDecoderReceiverStream
```

双向流的处理更简单——客户端发起的双向流是请求流，服务端收到后直接创建 `ResponseStream` 处理。

**流的分层继承**。所有流共享 `IStream` 基类（持有流类型和错误处理回调），然后分为 `ISendStream`（发送方向）和 `IRecvStream`（接收方向）。`ISendStream` 提供 `EnsureStreamPreamble()` 方法——首次调用时把流类型字节写入发送 buffer，后续调用跳过。这保证了 RFC 9114 §6.2 对单向流首字节的要求。`IRecvStream` 提供 `OnData()` 回调接口，由 QUIC 层在数据到达时调用。

**帧的编解码流**。帧不直接和 Connection 层对话——它们通过 Stream 层中转。以控制流的接收端为例，数据流向是：

```
QUIC RecvStream → ControlReceiverStream::OnData()
                            ↓
                   FrameDecoder::DecodeFrames()
                            ↓
            解码出 SettingsFrame / GoawayFrame 等
                            ↓
               HandleFrame() → 校验 + 回调
                            ↓
                Connection::HandleSettings() / HandleGoaway()
```

`FrameDecoder` 是有状态的——它持续存活在 `ControlReceiverStream` 内部，跨多次 `OnData()` 调用保持解码进度。这意味着一个帧可以分多次网络包到达，解码器不会丢失上下文。

**延迟销毁**。HTTP/3 流的生命周期管理有一个工程陷阱：流的回调函数可能在执行过程中触发流本身的销毁（比如解码出错导致关闭流），而此时回调还在调用栈上，直接销毁会导致 use-after-free。quicX 的解决方案是 `ScheduleStreamRemoval()`——把完成的流移到一个暂存区 `streams_to_destroy_`，通过定时器每 100ms 批量清理，确保销毁动作不会在回调栈上执行。

**配置的传播**。`Http3Settings` 结构体在 Connection 层构造时传入，通过 `AdaptSettings()` 转换为 wire 格式的 `<Identifier, Value>` map，然后编码进 SETTINGS 帧发送。收到对端的 SETTINGS 后，`HandleSettings()` 合并参数并校验保留 ID。QPACK 相关参数随后传递给 `QpackEncoder`，完成动态表容量和阻塞上限的初始化。

整个架构的分层可以这样概括：

```
┌─────────────────────────────────────────────────┐
│           Connection 层 (入口与生命周期)           │
│  IConnection → ClientConnection / ServerConnection │
│  - 创建控制流、QPACK 流                            │
│  - 流发现与分发（UnidentifiedStream）              │
│  - SETTINGS / GOAWAY 处理                         │
│  - 流的延迟销毁                                   │
├─────────────────────────────────────────────────┤
│            Stream 层 (职责分类)                    │
│  ISendStream (发送) / IRecvStream (接收)           │
│  - ControlSenderStream → 发送 SETTINGS/GOAWAY      │
│  - ControlReceiverStream → 接收 + FrameDecoder     │
│  - 各类专用流子类                                  │
├─────────────────────────────────────────────────┤
│             Frame 层 (编解码)                      │
│  IFrame → DataFrame / HeadersFrame / SettingsFrame │
│  FrameDecoder → 状态机驱动的增量解码               │
├─────────────────────────────────────────────────┤
│           QUIC Stream 层 (卷五)                    │
│  IQuicSendStream / IQuicRecvStream                 │
│  - 读写字节、流控、状态机                          │
└─────────────────────────────────────────────────┘
```

HTTP/3 层不直接操作 UDP，不管拥塞控制，不管 ACK——它只通过 QUIC Stream 接口读写字节。这正是 28.1 节所说的"职责重新划分"在工程中的体现：QUIC 管运输，HTTP/3 管语义，边界清晰，互不越界。
