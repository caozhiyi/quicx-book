# 34. 通天塔的阶梯：HTTP 协议协商与版本升级

一个 QUIC 库在实验室里只需要和自己对话——客户端发 Initial，服务端回 Handshake，双方都知道对方说的是同一种语言。但把同一个服务端放到公网上，第一个进来的请求很可能是 `GET / HTTP/1.1\r\n`。第二个可能是 HTTP/2 的 24 字节 Connection Preface。第三个才是 QUIC 长头部包。服务端不能挑客户端，它必须在同一个入口识别三种协议、选择最优版本、引导客户端升级。这不是锦上添花的兼容层，而是协议库进入真实世界的入场券。

---

## 34.1 多版本共存的现实：为什么不能只开 QUIC 端口

如果所有客户端都支持 HTTP/3，如果所有网络路径都允许 UDP，那协议升级根本不需要存在。现实恰好相反。

企业防火墙经常只放行 TCP 443，把 UDP 一律丢弃。老版本浏览器、嵌入式设备、某些代理网关只会说 HTTP/1.1。即使客户端支持 HTTP/3，第一次访问一个陌生域名时，它也不知道对端有没有 QUIC 入口——它只能先用 TCP 建连，等服务端告诉它"我这边有 HTTP/3"之后，才会在后台悄悄尝试 QUIC 握手。成功了，后续请求迁移到 HTTP/3；失败了，继续留在 TCP 上，用户毫无感知。

这就是浏览器的"探测-升级"策略。它揭示了一个核心事实：**HTTP/3 不是替代，而是叠加**。一个生产级服务必须同时服务三种协议——HTTP/1.1 用于兜底、HTTP/2 用于主力 TCP 连接、HTTP/3 用于 QUIC 路径可达时的最优体验。三者不是三代人的交替，更像同一栋楼的三个入口，服务端站在门厅里，根据来客的身份选择走哪条通道。

问题变成了：来客还没自报家门，服务端怎么判断他说的是什么语言？

---

## 34.2 三种协商机制：Upgrade 头、ALPN 扩展与 Alt-Svc 发现

三种 HTTP 版本的共存不是一种协商机制能覆盖的。它们出现在不同阶段、解决不同问题、适用不同场景。

**Upgrade 头：明文时代的老办法。** HTTP/1.1 到 HTTP/2 的明文升级（h2c 场景）走的是 HTTP 层协商：客户端在请求头里附上 `Connection: Upgrade, HTTP2-Settings` 和 `Upgrade: h2c`，服务端如果同意，返回 `101 Switching Protocols`，之后这条 TCP 连接就切换到 HTTP/2 帧协议。这个机制简单直接，但只能在未加密的 TCP 上工作——一旦上了 TLS，HTTP 头还没被解析，Upgrade 已经没有用武之地了。

**ALPN 扩展：握手里的暗号。** 当连接走 TLS 时，协议协商嵌入了握手过程。客户端在 TLS ClientHello 的 ALPN（Application-Layer Protocol Negotiation）扩展里列出自己支持的协议——比如 `h2, http/1.1`。服务端在 ServerHello 里从中选一个。协议版本在握手完成之前就已经确定，不需要额外的往返。ALPN 是 TLS 场景下的主力协商机制：HTTP/2 靠它、QUIC 握手中的 HTTP/3 协商也靠它。

**Alt-Svc 响应头：跨协议的路标。** 前两种机制都在同一条连接内完成协商。但 HTTP/3 跑在 UDP 上，和 TCP 连接不是同一条路——客户端不可能在一条 TCP 连接的 Upgrade 头里切换到 QUIC。解决方案是 Alt-Svc（Alternative Service）：服务端在 HTTP 响应头里附上 `Alt-Svc: h3=":443"; ma=86400`，告诉客户端"我在 UDP 443 端口有一个 HTTP/3 入口，有效期 24 小时"。客户端收到后在后台发起 QUIC 握手，成功了就把后续请求迁过去，失败了就当这个头不存在。Alt-Svc 是 HTTP/3 发现的**唯一途径**——没有它，客户端永远不知道该往哪里发 QUIC 包。

三种机制的适用边界清晰：Upgrade 头仅用于 TCP 明文、ALPN 是 TLS 连接的标配、Alt-Svc 是跨 TCP/UDP 的桥梁。一个完整的 HTTP 服务端需要同时实现三者。

---

## 34.3 从字节到协议：ProtocolDetector 的第一眼判断

三种协商机制回答了"怎么选版本"，但前提是服务端得先知道对面说的是什么。在 ALPN 之前、在 Upgrade 头被解析之前，TCP 连接上到达的第一批字节已经携带了足够的信息。

HTTP/2 的开场白是一段 24 字节的 Connection Preface：`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`。这是一个精心设计的魔数——它同时也是一段合法但必定失败的 HTTP/1.1 请求，如果被误送到只懂 HTTP/1.1 的服务器上，会收到一个明确的错误响应而不是静默挂起。服务端只需要比对前 24 字节，就能确认对方在说 HTTP/2。但 Connection Preface 不一定最先到达——有时候客户端会直接发一个 SETTINGS 帧或 PING 帧。quicX 的 `ProtocolDetector` 对此做了覆盖：如果头 24 字节不是 Preface，就解析 9 字节的帧头（3 字节长度 + 1 字节类型 + 1 字节 flags + 4 字节 stream_id），识别帧类型为 SETTINGS（0x04）、PING（0x06）、RST_STREAM（0x03）或 WINDOW_UPDATE（0x08）时也判定为 HTTP/2，还会额外校验 reserved bit 和 payload 长度是否合理。

HTTP/1.1 的辨识更直接：请求行以 ASCII 方法名开头——`GET `、`POST `、`PUT `、`DELETE `、`HEAD `、`OPTIONS `，后跟 URI 和版本号 `HTTP/1.1`。但仅匹配方法名前缀还不够，需要确认请求行里出现了 `HTTP/1.` 字样。quicX 的做法是扫描前 64 字节，全部转为小写后匹配方法名前缀，然后检查是否包含完整的请求行（至少有两个 CRLF——确保首行 header 也到了）。对于响应报文，检查前缀是否匹配 `HTTP/` 字样。

检测优先级也是讲究的：先尝试匹配 HTTP/2（因为 HTTP/2 的首字节模式比 HTTP/1.1 更确定——24 字节 Preface 或帧头），再尝试匹配 HTTP/1.1，两个都不匹配就返回 UNKNOWN。这种顺序避免了误判：一个 HTTP/2 客户端发的 `PRI` 不会被意外当成 HTTP/1.1 的方法名。

但首字节可能不够。如果客户端刚建连就发了 3 个字节，`GET` 三个字母看起来像 HTTP/1.1，但也可能是某个非标协议的前缀。quicX 的做法是：如果当前数据不足以做出判断，就返回 UNKNOWN，等下一批数据到达后追加再试。如果累积了 1KB 仍然无法识别——连接有问题，直接关闭。整个检测过程是纯内存比对，没有任何 I/O，开销可以忽略不计。

---

## 34.4 状态机驱动的升级流程：从检测到升级的四步走

协议检测只是第一步。从"知道对方说什么"到"成功升级到最优协议"，中间还有协商、响应生成、数据发送等多个环节，任何一步都可能阻塞或失败。quicX 用一个五状态的状态机来驱动整个升级生命周期。

连接建立时进入 **INITIAL** 状态。第一批数据到达后，`ProtocolDetector` 开始工作，连接进入 **DETECTING**。检测成功后，`VersionNegotiator` 接手协商，连接进入 **NEGOTIATING**——它决定当前协议能不能升级、升级到哪个版本、用什么方式告知客户端。协商成功且响应发送完毕后，连接进入 **UPGRADED**。任何阶段出错——检测失败、协商失败、响应发送失败——连接进入 **FAILED**，发送 400 错误后关闭。

`VersionNegotiator::Negotiate()` 的协商逻辑分三步：先调用 `ProtocolDetector::Detect()` 确认当前协议；再调用 `SelectBestProtocol()` 根据偏好顺序和 ALPN 结果选择目标协议；最后调用 `GenerateUpgradeStrategy()` 生成升级数据。

`SelectBestProtocol()` 的优先级链值得展开。如果当前已经是 HTTP/3——比如 ALPN 直接协商到了 h3——那就不需要升级，保持原样。如果 ALPN 列表中包含 `h3` 但检测到的是 HTTP/2 或 HTTP/1.1，说明客户端支持 HTTP/3 但走的是 TCP 路径，协商器选择升级到 HTTP/3。如果 `UpgradeSettings` 中 `enable_http3` 为 true 且检测到了 HTTP/1.1 或 HTTP/2，也会生成 Alt-Svc 引导。否则保持检测到的协议不变。这个逻辑的核心原则是：**能升则升，不强求**——升级失败不影响当前连接的正常服务。

升级数据的生成因协议而异。如果当前是 HTTP/1.1 需要升级到 HTTP/3，协商器生成一个完整的 HTTP/1.1 200 响应，携带 `Alt-Svc: h3=":<port>"; ma=86400` 头和 `Connection: close`。如果当前是 HTTP/2 需要升级到 HTTP/3，协商器手动构建两个二进制帧：一个空的 SETTINGS 帧（type=0x04，作为 server connection preface）和一个 ALTSVC 帧（type=0x0a，RFC 7838 定义的 HTTP/2 帧类型）。ALTSVC 帧的 payload 以 2 字节 Origin-Len（值为 0 表示 connection-wide）开头，后跟 `h3=":<port>"; ma=86400` 的 ASCII 值。

升级响应的发送不能假设一次写完。非阻塞 socket 上 `send` 可能返回 `EWOULDBLOCK` 或只写了一部分。`BaseSmartHandler` 用 `pending_response` 和 `response_sent` 两个字段跟踪发送进度：首次尝试写入，如果不完整就注册 WRITE 事件，等 socket 可写时继续发送，全部写完才切换到 UPGRADED。

超时是必须处理的场景。如果客户端建了 TCP 连接但不发任何数据，服务端不能永远等下去。quicX 在每个新连接建立时设置 30 秒超时定时器。如果在超时触发时连接仍处于 INITIAL、DETECTING 或 NEGOTIATING 状态，直接关闭。升级完成后定时器自动移除。

降级也是流程的一部分。`SmartHandlerFactory` 在创建 handler 时先尝试 HTTPS——如果 TLS 证书配置存在（文件路径或内存中的 PEM 对），就创建 `HttpsSmartHandler`；如果证书加载失败或未配置，不是报错退出，而是降级到 `HttpSmartHandler`，走明文 HTTP 路径。这种"尽最大努力提供服务"的策略在生产环境中是必要的：配置错误不应该让整个服务不可用，降级总比不可用好。

---

## 34.5 TLS 握手中的 ALPN 回调：嵌在握手里的决策点

HTTPS 场景下，协议协商不是在应用层发生的，而是嵌在 TLS 握手过程中。客户端在 ClientHello 的 ALPN 扩展里列出支持的协议，服务端在握手阶段通过回调函数选择最优协议，选择结果随 ServerHello 返回。等握手完成时，双方已经知道要用什么应用层协议——不需要额外的往返。

quicX 的 `HttpsSmartHandler` 在初始化 SSL 上下文时做两件事：一是通过 `SSL_CTX_set_alpn_select_cb` 注册 ALPN 选择回调 `ALPNSelectCallback`；二是通过 `SSL_CTX_set_alpn_protos` 设置服务端广告的协议列表——以 length-prefixed 格式编码，如 `{0x02, 'h', '3'}` 表示 "h3"。这个回调在每次 TLS 握手的 ClientHello 处理阶段被 OpenSSL（或 BoringSSL）调用。

`ALPNSelectCallback` 的逻辑直截了当：遍历客户端提供的协议列表，按服务端偏好顺序匹配。quicX 的 upgrade 模块优先选择 `h3`——如果客户端支持 HTTP/3 且走的是 TLS，直接在握手阶段确定协议。如果没有匹配项，返回 `SSL_TLSEXT_ERR_NOACK`，让握手继续但不选择任何协议——这意味着后续要靠字节检测来判断协议版本。

握手完成后，`HttpsSmartHandler` 通过 `SSL_get0_alpn_selected()` 读取协商结果，映射为内部的 `Protocol` 枚举（"h3" → HTTP3，"h2" → HTTP2，"http/1.1" → HTTP1_1）并存入连接上下文。在后续的 `HandleProtocolDetection` 中，这个 ALPN 结果的优先级高于字节检测——如果 ALPN 已经确定了协议，就不再需要检查首字节。

QUIC 层面的 ALPN 是同一个机制的另一个实例。QUIC 连接的 TLS 握手也携带 ALPN 扩展，HTTP/3 用它协商应用层协议标识 `h3`（RFC 9114 §3.1）。quicX 的 `TLSServerConnection` 在 `Init()` 中注册服务端 ALPN 回调，`ServerConnection::SSLAlpnSelect` 实现协议匹配。客户端侧由 `TLSClientConnection::AddAlpn()` 构造 ALPN 线格式（长度前缀 + 协议名）并设置到 SSL 对象上。当 Retry 发生时，`TLSClientConnection::Reset()` 会重置 TLS 状态但保留 ALPN 和 SNI 配置——确保重连后的协商参数不丢失。同一个 ALPN 机制在 TCP 和 QUIC 两个传输路径上各出现一次，但语义完全一致：在握手期间确定应用层协议。

---

## 34.6 QUIC 版本协商：传输层的另一场谈判

前面讲的协议协商都发生在应用层——HTTP/1.1、HTTP/2、HTTP/3 之间的选择。但 QUIC 自身也有版本，传输层也需要协商。这两层协商互不干扰：应用层协商决定"用什么 HTTP 版本"，传输层协商决定"用什么 QUIC 版本"。

客户端发出的 QUIC Initial 包在长头部中携带 32 位版本号。QUIC v1（RFC 9000）的版本号是 `0x00000001`，QUIC v2（RFC 9369）的版本号是 `0x6b3343cf`。quicX 的偏好序列是 `{kQuicVersion2, kQuicVersion1}`——v2 优先于 v1，默认使用 v2 发起连接。`SelectVersion()` 采用双重循环：外层按自身偏好顺序遍历 `kQuicVersions[]`，内层遍历对端提供的版本列表，第一个匹配即返回——保证选择的总是双方都支持的、己方最优先的版本。

如果服务端不认识客户端的版本号，它不会静默丢弃——而是回一个 **Version Negotiation Packet**。这个包的格式特殊：长头部中的 Version 字段强制为 0（这是它唯一的辨识标志），包体只包含服务端支持的版本列表（每个版本号占 4 字节），不加密、不包含帧。quicX 的包解码路径在遇到 version == 0 时就直接走 `VersionNegotiationPacket` 的解码逻辑，遇到版本号不在支持列表中时则丢弃包体、让上层发送 VN 响应。客户端收到后，从版本列表中选择一个自己也支持的版本，用新版本重新发起 Initial 握手。

这个流程有两个关键的安全考量。

第一是**防降级攻击**。如果客户端收到的 Version Negotiation Packet 中包含自己当前使用的版本——那说明服务端其实支持这个版本，这个包可能是中间人伪造的，目的是把连接降级到更弱的版本。quicX 的 `BaseConnection::OnVersionNegotiationPacket` 检测到这种情况后直接丢弃该包，不做任何响应。

第二是**防无限循环**。如果客户端已经经历过一次版本协商并重新建连，但又收到了新的 Version Negotiation Packet，说明协议出了问题——不可能反复协商下去。quicX 通过 `version_negotiation_done_` 标志位阻止二次协商，如果触发就以 `kProtocolViolation`（错误码 0x0a）关闭连接。

版本协商成功后，客户端需要关闭旧连接并创建新连接。quicX 的 `ClientWorker::HandleVersionNegotiation` 处理这个完整过程：先从 `connecting_set_` 和 `conn_map_` 中移除旧连接，取消该连接的握手超时定时器；然后用协商后的版本号创建新的 `ClientConnection`，在 `Dial()` 之前调用 `SetVersion(negotiated_version)` 设置版本和 `SetVersionNegotiationDone()` 标记已完成协商；接着注入 Sender、配置 Key Update、重新注册版本协商回调；最后调用 `Dial()` 发起新握手并重设超时定时器。整个过程对上层透明，但增加了一个 RTT 的延迟。整条逻辑中最关键的一步是 `SetVersionNegotiationDone()`——它确保新连接如果再次收到 VN 包，会立即中止而不是再次尝试协商，从根本上切断了循环的可能。

RFC 9369 引入的 **Compatible Version Negotiation** 是这个开销的优化方案。它不再依赖 Version Negotiation Packet 的额外往返，而是让双方在传输参数中声明自己支持的版本列表。如果客户端发的是 v1 但传输参数里列出了 v2，且服务端也支持 v2，双方可以在握手过程中直接"升级"到 v2——不需要重新建连，不需要额外的 RTT。这种机制的前提是两个版本在密钥调度和头部格式上是兼容的——这正是"compatible"的含义。

---

## 34.7 从应用层到传输层：三层协商的全景

从应用层的 Upgrade 头和 Alt-Svc，到 TLS 的 ALPN 扩展，再到 QUIC 传输层的版本协商——三层协商各自解决不同粒度的问题。

Upgrade 头工作在 HTTP 语义层，解决的是明文连接上的版本切换。ALPN 工作在 TLS 握手层，解决的是加密连接上的应用协议选择。Alt-Svc 工作在 HTTP 响应层，解决的是跨传输协议（TCP → UDP）的服务发现。Version Negotiation Packet 工作在 QUIC 传输层，解决的是 QUIC 版本本身的兼容性。

它们的共同点是：没有哪一层敢假设"对面一定和我一样"。

quicX 的 `UpgradeSettings` 结构把所有这些层次的配置统一收拢：`enable_http1`、`enable_http2`、`enable_http3` 三个开关控制应用层支持；`preferred_protocols` 列表（默认 `{"h3", "h2", "http/1.1"}`）定义偏好顺序；`cert_file` 和 `key_file`（或内存中的 `cert_pem` 和 `key_pem`）控制 TLS 是否可用；`detection_timeout_ms`（默认 5 秒）和 `upgrade_timeout_ms`（默认 10 秒）控制各阶段的超时容忍度。这些配置项背后的共同假设是：互联网不会在一夜之间统一到一个协议上。渐进升级的本质，决定了协议库不能只为理想情况编码，它必须为所有可能的来客准备好应答。
