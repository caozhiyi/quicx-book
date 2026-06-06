# 29. 重新映射：从 QUIC 流到请求与响应

帧体系和流类型给了 HTTP/3 一套语法——七种帧各有分工，五类流各有身份。但语法本身不回答最基本的问题：一次 HTTP 请求是怎么发出去的，响应又是怎么收回来的？客户端打开一条双向流之后，先发什么帧、后发什么帧、什么时候算发完、什么时候算收完？这些问题的答案构成了 HTTP/3 的**数据面**——帧和流的使用手册。

---

## 29.1 Pseudo-header 为什么仍然存在

HTTP/1.1 的请求有一行开头：`GET /index.html HTTP/1.1`。这行文本携带了三个信息——方法、路径、协议版本。到了 HTTP/2，文本行消失了，取而代之的是四个以冒号开头的特殊字段：`:method`、`:scheme`、`:authority`、`:path`。HTTP/3 完整继承了这套设计，并补充了响应侧的 `:status`。

这五个字段叫做**伪头部**（pseudo-header fields）。它们不是普通的 HTTP 头字段——不能出现在 Trailers 里，不能在普通头字段之后发送，名字必须以冒号开头。RFC 9114 §4.3 要求：所有伪头部必须出现在头部块（header block）的最前面，接收方如果在普通头字段之后看到伪头部，必须视为格式错误（malformed）。

为什么不用帧的某个字段来传方法和路径，偏要塞进头部块里？原因是 HTTP/3 的头部块会被 QPACK 压缩（第 30 章展开）。如果方法和路径放在帧的固定字段里，它们就无法参与压缩——而 `:method: GET` 和 `:path: /` 是所有请求中出现频率最高的字段，压缩收益极大。把它们放进头部块，让 QPACK 统一处理，是一个"用格式约束换压缩收益"的工程决策。

请求侧必须携带四个伪头部：

| 伪头部 | 含义 | 示例 |
|--------|------|------|
| `:method` | HTTP 方法 | `GET`、`POST` |
| `:scheme` | 协议方案 | `https` |
| `:authority` | 目标主机（等价于 Host） | `example.com:443` |
| `:path` | 请求路径（含查询串） | `/api/users?page=1` |

响应侧只有一个：`:status`，值为三位数字的状态码（如 `200`、`404`）。

quicX 用 `PseudoHeader` 类（单例模式）集中处理伪头部的编解码。在发送请求时，`PseudoHeader::EncodeRequest()` 把 `IRequest` 对象上的 `method`、`path`、`scheme`、`authority` 四个字段写进 headers map，键名加上冒号前缀。在接收请求时，`PseudoHeader::DecodeRequest()` 做逆操作：从 headers map 中提取四个伪头部字段，设置到 `IRequest` 对象上，然后把这四个键从 map 中移除——后续应用代码拿到的 headers 里只有普通头字段，不会看到冒号开头的东西。

验证逻辑嵌在解码过程中：请求必须有 `:method` 和 `:path`，响应必须有 `:status`——缺失或重复都会触发帧格式错误，导致流被重置。

---

## 29.2 HEADERS 与 DATA 如何组成请求和响应

伪头部解决了"语义锚点"的问题，但它只是头部块的一部分。一次完整的 HTTP 交互需要在一条 QUIC 双向流（Request Stream）上按特定顺序排列帧。RFC 9114 §4.1 定义了这个序列：

**客户端 → 服务端（请求）**：

```
HEADERS 帧（请求头 + 伪头部）
DATA 帧 × 0..N（请求体，可以没有）
HEADERS 帧 × 0..1（Trailers，可选）
FIN（QUIC 流半关闭）
```

**服务端 → 客户端（响应）**：

```
HEADERS 帧（响应头 + :status 伪头部）
DATA 帧 × 0..N（响应体，可以没有）
HEADERS 帧 × 0..1（Trailers，可选）
FIN（QUIC 流半关闭）
```

几个关键约束值得注意。第一，HEADERS 帧的 payload 不是人类可读的文本——它是 QPACK 编码后的字节流。帧本身不知道里面装了什么头字段，它只负责搬运一段字节；QPACK 编解码是独立的步骤（第 30 章展开）。第二，DATA 帧可以有多个——一个大的请求体或响应体会被切成多个 DATA 帧发送，每个帧的大小受 QUIC 流的发送窗口和应用层缓冲策略约束。第三，FIN 是 QUIC 层的信号，不是 HTTP/3 层的帧——客户端发完请求后通过关闭 QUIC 流的发送方向来表示"请求体已完整"。

这里有一个容易混淆的点：**HTTP/3 没有 END_STREAM 标志**。HTTP/2 用帧标志位（END_STREAM flag）来标记消息结束，HTTP/3 取消了这个设计——QUIC 流的 FIN 机制天然提供了"这一方向没有更多数据"的语义，不需要在应用层重复。

一个具体的例子：客户端请求 `GET /api/users`。

1. 客户端打开一条双向流（Stream ID = 0，客户端发起的第一条双向流）
2. 构造请求头：`:method: GET`、`:scheme: https`、`:authority: example.com`、`:path: /api/users`、`accept: application/json`
3. QPACK 编码请求头 → 得到一段字节
4. 封装为 HEADERS 帧（Type=0x01, Length=编码后长度, Payload=编码后字节）
5. 写入 QUIC 流
6. 没有请求体，直接发送 FIN（QUIC 流半关闭发送方向）
7. 服务端收到 HEADERS 帧 → QPACK 解码 → 提取伪头部 → 路由到对应 Handler
8. Handler 处理后构造响应：`:status: 200`、`content-type: application/json`、body = `[{"id":1,"name":"Alice"}]`
9. 响应编码为 HEADERS 帧 + DATA 帧 → 写入 QUIC 流 → FIN

整个交互在一条 QUIC 双向流上完成。客户端如果要同时发多个请求，每个请求占一条独立的双向流——这就是 QUIC 原生多路复用的体现，不需要 HTTP/2 那种应用层的流 ID 多路复用。

---

## 29.3 流式处理与完整缓冲两种模型

上一节描述的帧序列有一个隐含问题：接收方收到第一个 DATA 帧时，应该立即处理，还是等所有 DATA 帧到齐后再处理？

这是两种截然不同的数据处理模型：

**完整缓冲**（Buffered）：等所有数据收齐后一次性交给应用。适合体积小、语义完整的场景——比如一个 JSON API 响应，应用需要拿到完整 JSON 才能解析。代价是内存占用和延迟：如果响应体很大，接收方需要缓冲全部数据。

**流式处理**（Streaming）：每收到一个 DATA 帧就立即交给应用。适合大文件下载、视频流、Server-Sent Events 等场景。应用在第一个数据块到达时就可以开始工作，不需要等完整消息。代价是应用代码的复杂度——需要处理数据到达的边界、中断、乱序等情况。

HTTP/3 协议本身不强制选择哪种模型——它只保证帧按顺序到达（同一条 QUIC 流内有序）。选择权交给实现。

quicX 通过 `RouteConfig` 的 variant 类型同时支持两种模型。`RouteConfig` 内部是一个 `std::variant<http_handler, shared_ptr<IAsyncServerHandler>, shared_ptr<IAsyncClientHandler>>`——如果应用注册的是 `http_handler`（一个普通回调函数），quicX 使用完整缓冲模式，等请求头和请求体全部到齐后一次性调用；如果应用注册的是 `IAsyncServerHandler`，quicX 使用流式模式。

流式模式的回调序列是：

1. 收到请求头 → `OnHeaders(request, response)` — 此时 body 尚未到达，应用可以检查请求头并决定如何处理
2. 每收到一块请求体 → `OnBodyChunk(data, length, is_last)` — 可能被调用多次
3. 最后一次 `OnBodyChunk` 的 `is_last=true` 标志请求体接收完毕

客户端侧对称：`IAsyncClientHandler` 在收到响应头时触发 `OnHeaders(response)`，然后逐块接收响应体。

完整缓冲模式更简单：quicX 在内部把所有 DATA 帧的数据累积到一个 buffer 里，拼接完成后创建完整的 `IRequest` 对象（body 可以通过 `GetBody()` 或 `GetBodyAsString()` 一次性获取），然后调用 `http_handler(request, response)`。

两种模式的切换发生在路由匹配时——同一个服务可以为不同的路径注册不同的处理模式。文件上传接口用流式模式避免把整个文件缓冲到内存，普通 API 接口用完整缓冲模式简化应用代码。

---

## 29.4 Handler、Router 与应用回调的落点

帧解码、伪头部提取、数据缓冲都是协议栈内部的事情。应用开发者关心的是：**我的业务代码在哪里被调用？**

quicX 的请求处理链路从 QUIC 字节到应用回调经过五个阶段：

```
QUIC Stream 回调
    → FrameDecoder 解帧
        → QPACK 解码头部
            → PseudoHeader 提取方法和路径
                → Router 匹配路由
                    → Handler 业务处理
```

`IRouter` 是路由分发的接口。应用在启动时通过 `AddRoute(method, path, config)` 注册路由规则——`method` 是 HTTP 方法（GET、POST 等，支持 `kAny` 通配），`path` 是路径模式，`config` 是处理函数或异步 Handler。

quicX 的 `Router` 实现是一棵**前缀树**（trie）。每个 HTTP 方法维护一棵独立的树，树节点有三种类型：

- `RouterNodeStaticPath`：静态路径段，精确匹配。如 `/users`
- `RouterNodeDynamicParam`：动态参数段，匹配任意值并提取参数。如 `/:id` 匹配 `/123`，提取 `id=123`
- `RouterNodeWildcard`：通配符，匹配路径末尾的所有内容。如 `/*` 匹配 `/static/css/style.css`

匹配优先级是**静态 > 动态参数 > 通配符**。这意味着 `/users/profile` 优先于 `/users/:id`，后者优先于 `/users/*`。路径参数在匹配过程中被提取到 `MatchResult.params` 中，应用可以通过 `request->GetPathParams()` 获取。

匹配成功后，quicX 进入 Handler 调用阶段。`ResponseStream` 内部定义了 `IHttpProcessor` 接口，提供三个钩子：

1. `MatchRoute(method, path, request)` — 路由匹配，返回 `RouteConfig`
2. `BeforeHandlerProcess(request, response)` — 前置中间件，在 Handler 之前执行
3. `AfterHandlerProcess(request, response)` — 后置中间件，在 Handler 之后执行

这三个钩子让 quicX 的请求处理具备了中间件能力——日志记录、鉴权检查、响应压缩等横切关注点可以在 Before/After 中统一处理，不需要侵入每个 Handler。

Handler 处理完成后，`ResponseStream` 调用 `SendResponse()`：先编码伪头部（`:status`），然后 QPACK 编码全部响应头，封装为 HEADERS 帧写入 QUIC 流，接着把响应体封装为 DATA 帧（支持分块发送和 provider 模式），最后发送 FIN。

客户端侧的发起路径是对称的：`ClientConnection::DoRequest()` 接收一个 `IRequest` 对象和一个回调函数（或异步 Handler），内部调用 QUIC 连接的 `MakeStreamAsync()` 创建双向流，然后构造 `RequestStream` 发送请求。创建流的操作是异步的——如果当前并发流数已达到 `MAX_STREAMS` 上限（卷五第 26 章），请求会排队等待额度释放。

---

## 29.5 HTTP/3 错误码与错误传播链路

请求处理过程中任何一个环节都可能出错——帧格式非法、伪头部缺失、QPACK 解码失败、Handler 抛异常、服务端主动拒绝请求。HTTP/3 为这些错误定义了一套独立的错误码体系，编号从 `0x0100` 开始，与 QUIC 传输层的错误码（`0x00`-`0x0F`）不重叠。

错误码按**影响范围**分为两类：

**流级错误**——只影响单条请求，不影响连接上的其他请求：

| 错误码 | 值 | 含义 |
|--------|----|------|
| `H3_REQUEST_REJECTED` | 0x010B | 服务端拒绝请求（未处理，客户端可以安全重试） |
| `H3_REQUEST_CANCELLED` | 0x010C | 请求被取消（客户端或服务端主动取消） |
| `H3_REQUEST_INCOMPLETE` | 0x010D | 请求未完整接收（流被意外关闭） |

流级错误通过 QUIC 的 `RESET_STREAM` 帧传播。发送方在 `RESET_STREAM` 帧中携带 HTTP/3 错误码，接收方通过错误码判断发生了什么——`H3_REQUEST_REJECTED` 意味着服务端还没看请求内容就拒绝了（通常是过载保护），客户端可以安全地重新发送；`H3_REQUEST_CANCELLED` 则表示某一方主动放弃了这次请求。

**连接级错误**——影响整条连接，所有正在进行的请求都会被终止：

| 错误码 | 值 | 含义 |
|--------|----|------|
| `H3_GENERAL_PROTOCOL_ERROR` | 0x0101 | 未分类的协议错误 |
| `H3_INTERNAL_ERROR` | 0x0102 | 内部实现错误 |
| `H3_STREAM_CREATION_ERROR` | 0x0103 | 流创建违规 |
| `H3_CLOSED_CRITICAL_STREAM` | 0x0104 | 关键流被关闭 |
| `H3_FRAME_UNEXPECTED` | 0x0105 | 帧出现在不允许的流类型上 |
| `H3_FRAME_ERROR` | 0x0106 | 帧格式错误 |
| `H3_EXCESSIVE_LOAD` | 0x0107 | 超出资源限制 |
| `H3_ID_ERROR` | 0x0108 | Stream ID 或 Push ID 错误 |
| `H3_SETTINGS_ERROR` | 0x0109 | SETTINGS 帧格式或内容错误 |
| `H3_MISSING_SETTINGS` | 0x010A | 控制流上未收到 SETTINGS 帧 |
| `H3_MESSAGE_ERROR` | 0x010E | HTTP 消息格式错误 |
| `H3_CONNECT_ERROR` | 0x010F | CONNECT 方法错误 |

连接级错误通过 QUIC 的 `CONNECTION_CLOSE` 帧传播——一旦发送，连接进入关闭流程，所有流被终止。

还有三个 QPACK 相关的错误码，同样是连接级别的：

| 错误码 | 值 | 含义 |
|--------|----|------|
| `QPACK_DECOMPRESSION_FAILED` | 0x0200 | QPACK 解压失败 |
| `QPACK_ENCODER_STREAM_ERROR` | 0x0201 | QPACK 编码器流错误 |
| `QPACK_DECODER_STREAM_ERROR` | 0x0202 | QPACK 解码器流错误 |

QPACK 错误为什么是连接级的？因为 QPACK 的动态表是连接级共享的——一旦编码器流或解码器流出错，动态表状态就不可信了，所有后续的头部解码都可能出错。唯一安全的做法是关闭整条连接。

这套错误码体系的设计逻辑是：**能隔离到单条流的错误就隔离，不能隔离的才升级为连接级**。帧格式错误虽然严重，但如果只出现在一条请求流上，理论上可以只重置该流——然而 RFC 9114 §8 要求，某些帧格式错误（如控制流上的帧错误）必须作为连接级错误处理，因为它们影响了连接的全局状态。

quicX 中，`IConnection` 基类的 `HandleError(stream_id, error_code)` 是错误处理的汇聚点。当 `error_code` 为 0 时（`H3_NO_ERROR`），表示流正常完成，调用 `ScheduleStreamRemoval()` 延迟清理；当 `error_code` 非 0 时，根据错误类型决定是重置流还是关闭连接。连接级错误调用 QUIC 连接的 `Close(error_code)`，流级错误调用流对象的 `Reset(error_code)`。

---

## 29.6 Server Push：设计初衷、协议机制与被淘汰的启示

Server Push 是 HTTP/3 中最有争议的特性——它在协议规范中占了相当篇幅，在 quicX 中有完整实现，但在真实世界中几乎没有被使用。这个"协议支持但工程上失败"的案例，值得用一节来讲清楚。

**设计初衷**。浏览器请求一个 HTML 页面后，通常紧接着会请求页面引用的 CSS、JavaScript、图片等资源。传统模式下，浏览器必须先解析 HTML，发现资源引用，再逐个发起请求——每个资源至少多一个 RTT。Server Push 的想法是：服务端在返回 HTML 的同时，主动把 CSS 和 JS 也推过去，省掉浏览器发现和请求资源的时间。

**协议机制**。Push 涉及三种帧和两类流：

1. 服务端在**请求流**上发送 `PUSH_PROMISE` 帧——帧内携带一个 Push ID 和 QPACK 编码的请求头（告诉客户端"我要推送这个 URL 的响应"）
2. 服务端随后打开一条**单向推送流**（Stream Type=0x01），在流开头写入 Push ID，然后发送 HEADERS 帧和 DATA 帧——这就是推送的响应内容
3. 客户端通过 `MAX_PUSH_ID` 帧控制服务端可以使用的 Push ID 上限——如果 `MAX_PUSH_ID` 为 0，推送被完全禁止
4. 客户端可以通过 `CANCEL_PUSH` 帧取消一个尚未开始传输的推送——如果资源已经在缓存中，推送就是浪费

Push ID 是一个连接级的单调递增标识符，与 QUIC Stream ID 无关。每个 PUSH_PROMISE 帧分配一个唯一的 Push ID，对应的推送流在开头也携带相同的 Push ID，客户端通过 ID 将承诺和实际数据关联起来。

quicX 中，`ServerConnection` 管理推送的完整流程。当 Handler 在 `IResponse` 上调用 `AppendPush(push_response)` 添加推送响应后，`ResponseStream` 在发送完主响应后触发推送处理。`ServerConnection::HandlePush()` 为每个推送响应分配 Push ID，在请求流上发送 `PUSH_PROMISE` 帧，然后启动一个定时器（`kServerPushWaitTimeMs`）等待——给客户端时间发送 `CANCEL_PUSH`。如果定时器到期后该 Push ID 未被取消，`ServerConnection` 创建单向流，通过 `PushSenderStream::SendPushResponse()` 发送推送数据。

客户端侧，`PushReceiverStream` 通过一个两阶段状态机处理推送流：先读取 Push ID（`kReadingPushId`），再解码 HEADERS 和 DATA 帧（`kReadingFrames`）。解码完成后通过 `http_response_handler` 回调通知应用。

**为什么被淘汰**。机制看起来完整，但在真实场景中 Push 几乎总是弊大于利：

第一，**服务端无法准确预测客户端需要什么**。如果客户端已经缓存了 CSS 文件，服务端的推送就是纯粹的带宽浪费。服务端不知道客户端的缓存状态，也不知道 Service Worker 是否会拦截请求。

第二，**Push 与浏览器缓存的交互极其复杂**。推送的响应是否应该进入 HTTP 缓存？如果进入，缓存键是什么？如果客户端已经有一个同 URL 的缓存条目，推送的版本是否应该覆盖它？这些问题在不同浏览器中有不同的实现，行为不可预测。

第三，**Push 的时机控制很难做对**。服务端在发送 HTML 的同时推送 CSS，但如果客户端的网络很慢，推送的 CSS 可能和 HTML 竞争带宽，反而拖慢了页面渲染。

第四，**更轻量的替代方案出现了**。103 Early Hints 允许服务端在正式响应之前发送一个"提示"响应，告诉浏览器"你接下来可能需要这些资源，可以提前发起请求"。这种方式比 Push 简单得多——服务端只发提示，不发数据，决策权留给客户端。

Chrome 在 2022 年移除了 HTTP/2 Push 支持。Firefox 和 Safari 也基本不再投入。HTTP/3 的 Push 虽然在协议规范中保留，但实际处于"可选但无人使用"的状态。

这个故事对协议设计有一个深刻的教训：**复杂的"智能"特性往往败给简单的"提示"机制**。Push 试图让服务端替客户端做决策，但服务端永远没有客户端了解自己的状态。103 Early Hints 把决策权还给客户端，反而更实用。协议设计者需要警惕"我们可以替对方想好一切"的诱惑。

---

## 29.7 quicX 的 Request / Response Stream 设计

前面六节分别讲了伪头部、帧序列、处理模型、路由分发、错误体系和 Server Push。这一节把它们收束到一张完整的图上——quicX 如何把这些组件组装成一个可运行的请求处理管线。

整个管线的核心是三层继承：

```
IStream（HTTP/3 层流基类，持有流类型和错误回调）
    └── ReqRespBaseStream（请求/响应流公共基类）
            ├── RequestStream（客户端侧）
            └── ResponseStream（服务端侧）
```

`ReqRespBaseStream` 封装了所有公共逻辑——帧解码（`FrameDecoder`）、QPACK 编解码（通过持有 `QpackEncoder` 和 `QpackBlockedRegistry` 的引用）、HEADERS 帧和 DATA 帧的发送与接收。它定义了两个纯虚方法让子类实现差异化行为：`HandleHeaders()` 和 `HandleData()`。

`ReqRespBaseStream` 有一个重要的设计约束：**构造和初始化必须分两步**。构造函数只保存参数，`Init()` 方法注册 QUIC 流的读写回调。分离的原因是 `ReqRespBaseStream` 使用了 `enable_shared_from_this`——在构造函数中调用 `shared_from_this()` 会导致未定义行为（对象还没被 `shared_ptr` 管理）。所有创建 `RequestStream` 或 `ResponseStream` 的地方都必须先 `make_shared`，再调用 `Init()`。

数据接收的完整路径：

```
QUIC Stream 数据到达
  → ReqRespBaseStream::OnData(data, is_last, error)
    → FrameDecoder::DecodeFrames(data)  // 可能解出 0..N 个帧
      → 对每个帧调用 HandleFrame(frame)
        → HEADERS 帧：QPACK 解码
            → 如果解码因动态表未就绪而阻塞
                → 注册到 QpackBlockedRegistry，等待通知后重试
            → 如果解码成功
                → 调用子类的 HandleHeaders()
        → DATA 帧：提取 payload
            → 调用子类的 HandleData(data, is_last)
```

帧解码有一个精细的 `is_last` 追踪机制。一次 `OnData` 回调可能带来多个帧的数据，但只有批次中的最后一个帧才应该被标记为 `is_last`。`ReqRespBaseStream` 通过 `current_frame_is_last_` 成员追踪这个状态，确保中间帧不会误触发"消息结束"的逻辑。

**RequestStream**（客户端侧）的职责是发送请求、接收响应。`SendRequest()` 的流程：`PseudoHeader::EncodeRequest()` 注入伪头部 → 添加 `content-length`（如果有 body）→ `SendHeaders()` → `SendBodyDirectly()` 或 `SendBodyWithProvider()`。收到响应时，`HandleHeaders()` 创建 `IResponse` 对象、解码伪头部（提取 `:status`）、记录 Metrics（按状态码分类：2xx/3xx/4xx/5xx）。

RequestStream 还有一个关键的虚方法返回值：`ShouldSignalCompletionAfterSend()` 返回 `false`。这意味着发完请求后流不会被标记为完成——它还需要等待响应。只有收到完整响应后，`error_handler_(stream_id, 0)` 才会被调用，通知连接层该流已完成。

**ResponseStream**（服务端侧）的职责是接收请求、发送响应。它额外持有 `IHttpProcessor` 引用，在收到请求头后调用 `MatchRoute()` 进行路由匹配，然后根据匹配结果选择完整模式或流式模式处理。`ShouldSignalCompletionAfterSend()` 返回 `true`——服务端发完响应后流就完成了。

ResponseStream 在处理请求前还会检查一个前置条件：**SETTINGS 帧是否已收到**。RFC 9114 要求双方在控制流上交换 SETTINGS 帧后才能处理请求——如果请求到达时 SETTINGS 尚未就绪，ResponseStream 会通过 `settings_received_cb` 注册等待回调。

最后是流的生命周期管理。请求处理完成后，连接层通过 `ScheduleStreamRemoval()` 将流对象移入 `streams_to_destroy_` 队列，而不是立即删除。延迟销毁防止了一个经典问题：在回调栈中删除自身导致 use-after-free。`HandleSent` 回调中进一步使用 `weak_ptr` 来检测流是否已被销毁——双重保险确保异步操作的安全性。

下面这张图展示了一次完整请求的端到端路径：

```
客户端                                          服务端
  │                                               │
  │ DoRequest(request, handler)                    │
  │   → MakeStreamAsync(kBidi)                     │
  │   → RequestStream::SendRequest()               │
  │     → PseudoHeader::EncodeRequest()            │
  │     → QPACK 编码                               │
  │     → HEADERS 帧 ──────────────────────────→  HandleStream(bidi)
  │     → DATA 帧(s) ─────────────────────────→    → ResponseStream::Init()
  │     → FIN ─────────────────────────────────→    │
  │                                                │ OnData → FrameDecoder
  │                                                │ → HEADERS: QPACK 解码
  │                                                │   → DecodeRequest()
  │                                                │   → Router::Match()
  │                                                │   → Before → Handler → After
  │                                                │ → DATA: 累积 body
  │                                                │
  │                                                │ SendResponse()
  │  ←──────────────────────── HEADERS 帧（:status） │
  │  ←──────────────────────── DATA 帧(s)           │
  │  ←──────────────────────── FIN                  │
  │                                               │
  │ HandleHeaders → DecodeResponse()               │
  │ HandleData → 累积/流式回调                      │
  │ response_handler_(response, 0)                 │
  │ error_handler_(stream_id, 0) → 流完成          │
  │                                               │
```

这张图里的每一步在前六节都有对应的机制说明。伪头部在 29.1，帧序列在 29.2，处理模型在 29.3，Router 和 Handler 在 29.4，错误处理在 29.5。它们共同构成了 HTTP/3 数据面的完整画面——从应用发起请求到收到响应，每一步都有明确的协议规则和 quicX 的工程实现。
