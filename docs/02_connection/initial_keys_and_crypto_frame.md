# 7. 公开的秘密：Initial 密钥与 CRYPTO Frame 的起步逻辑

每一个加密协议都必须面对同一个鸡生蛋的困境：你想加密通信，可加密需要密钥，而密钥本身也得通过通信来协商。TCP + TLS 的解法是把这两件事拆成两步串行完成——先用明文建连，再用明文跑完密钥协商，最后才切换到加密传输。QUIC 不满足于这个方案。它想从第一个包开始就穿上加密的外壳，哪怕这层外壳并不坚不可摧。

本章要拆解的，就是 QUIC 怎么做到这一点：用什么材料造出第一把密钥，又用什么管道把握手消息可靠地送到对端。

---

## 7.1 串行时代的代价：传统 TLS 握手为什么总要多等一步

要理解 QUIC 的第一个包为什么必须加密，我们得先看清楚传统 TLS 握手在 TCP 身上踩过的那道坑。

在 TLS + TCP 的经典架构里，加密和传输是串行工作的。TCP 先上场——它得先把三次握手走完，确保这条可靠的字节流已经建立起来，TLS 这才有机会登场。TLS 握手本质上是一组加密协商消息的往返：客户端发 ClientHello，服务端回 ServerHello，然后双方交换密钥材料，最后握手完成，应用数据才能开始传输。

用一张时序图来看，整个过程大致是这样的：

```
客户端                                          服务端
  │                                              │
  │  ──────── TCP SYN ────────────────────────>  │
  │                                              │  ┐
  │  <─────── TCP SYN-ACK ────────────────────   │  │ TCP 三次握手
  │                                              │  │ ~1.5 RTT
  │  ──────── TCP ACK ────────────────────────>  │  ┘
  │                                              │
  │  ──────── TLS ClientHello ────────────────>  │
  │                                              │  ┐
  │  <─────── TLS ServerHello ────────────────   │  │ TLS 握手
  │  <─────── Certificate, Finished ──────────   │  │ 1 RTT
  │                                              │  │
  │  ──────── TLS Finished ───────────────────>  │  ┘
  │                                              │
  │  ══════ 加密应用数据开始传输 ════════════════  │
  │                                              │
         总计：约 2.5 RTT 之后才能发送第一字节应用数据
```

注意看这张图的上半部分：TCP 三次握手走完之前，TLS 连开口的机会都没有。ClientHello 必须等三次握手收尾的那个 ACK 发出去之后才能上路。

这个串行结构看起来天经地义，但只要你仔细算一笔账，就会发现它有个隐蔽的代价——**TLS 必须等 TCP 把路铺平了才能开始铺自己的路**。TLS 1.3 本身只需要 1-RTT 就能完成握手，但加上 TCP 的三次握手，总共要 2.5 个往返才能发出第一字节应用数据。

在有线网络时代，这 1.5 个额外往返可能无伤大雅——毕竟网线一插，电光火石之间，三次握手就完成了。但到了移动网络时代，这 1.5 个往返突然变得昂贵起来。想象一下，你的手机正在用 4G 网络，信号翻过一座山、穿过一条隧道，延迟从 50ms 突然跳到 300ms。在这种环境下，TCP 三次握手的那 1.5 个往返就显得格外漫长——每次你打开一个 HTTPS 链接，都要先等 TCP 把路铺好，TLS 才能进场。

更关键的问题在于：**TCP 和 TLS 这两层的等待是相互独立的，但它们又必须串行执行**。TLS 没办法提前开始——它必须等 TCP 可靠；TCP 也没法为 TLS 提速——它只能保证自己这层的可靠。这种"层层叠加"的串行结构，本质上是在浪费每一个 RTT。

QUIC 想要打破的就是这个僵局。既然 TCP 和 TLS 各自都要走一遍"建立连接→交换密钥"的流程，QUIC 为什么不把它们拧成一股绳，让第一次握手消息就带着加密外壳直接上路？这就是 QUIC 最初的设计冲动——**把"建连"和"加密"这两件事，从串行改成并行**。

但并行带来了一个新问题。TCP + TLS 的世界里，握手消息是明文跑在已建立的 TCP 连接上的——ClientHello 和 ServerHello 本身不加密，加密要等握手完成才开始。QUIC 既然要从第一个包就穿上加密外壳，那在双方还没协商出任何共享密钥的时候，这层加密拿什么来做？

---

## 7.2 公开的秘密：Initial Secret 为什么能撬开死循环

死循环摆在面前：QUIC 想说"我要和你加密通信"，但没有加密密钥怎么开口？

QUIC 的解决方案既简单又大胆——**用一把"公开的秘密"先把第一把火点着**。

这把钥匙叫做 **Initial Secret**。它的派生过程不需要任何预共享密钥，也不需要双方提前约好的密码——它只需要两个公开的输入：一个是客户端随机生成的 **Destination Connection ID**（简称 DCID），另一个是 QUIC 协议规范里写死的 **Initial Salt**。

具体怎么派生其实很简单，整个过程分两步走：客户端首先生成一个随机数作为 DCID，然后把这个 DCID 和 QUIC 协议规定的 Initial Salt 一起塞进 HKDF-Extract，提取出一个中间密钥（init_secret）；接着再用 HKDF-Expand 从这个中间密钥分别派生出客户端和服务端各自的 Initial Secret。客户端用属于自己方向的密钥给第一个 Initial Packet 加上保护，然后发给服务端。

服务端收到这个包之后，它并不是在解密之前就已经知道密钥——而是通过一个逆向的过程：它从 Initial Packet 的包头里拿出 Destination Connection ID（这部分是明文，因为路由需要它），而这个 DCID 正是客户端随机生成的那个值。服务端用这个 DCID 和同样的 Initial Salt 跑一遍同样的 HKDF 派生流程，**推导出和客户端一模一样的 Initial Secret**。这一步不需要任何额外的协商消息，因为 Salt 是公开的、DCID 是明文来的，双方各自算一遍，结果必然相同。

这就是为什么我们把它叫做"公开的秘密"——**密钥的原材料就在数据包本身上裸着跑，任何中间盒都看得见，但最终派生出来的密钥，只有通信双方自己知道**。

在 quicX 的实现里，这个派生过程落在 `AeadBaseCryptographer::InstallInitSecret()`（`src/quic/crypto/aead_base_cryptographer.cpp`）：

```cpp
ICryptographer::Result AeadBaseCryptographer::InstallInitSecret(
    const uint8_t* secret, size_t secret_len,
    const uint8_t* salt, size_t saltlen, bool is_server) {
    const EVP_MD* digest = EVP_sha256();

    // 第一步：HKDF-Extract，从 DCID + Salt 提取中间密钥
    uint8_t init_secret[kMaxInitSecretLength] = {0};
    Hkdf::HkdfExtract(init_secret, kMaxInitSecretLength,
                       secret, secret_len, salt, saltlen, digest);

    // 第二步：HKDF-Expand，分别派生客户端和服务端的 Initial Secret
    // 服务端视角：read = client, write = server
    // 客户端视角：read = server, write = client（下面 swap 实现）
    const uint8_t* read_label = kTlsLabelClient.data();  // "tls13 client in"
    const uint8_t* write_label = kTlsLabelServer.data();  // "tls13 server in"
    if (!is_server) {
        std::swap(read_label, write_label);
    }

    uint8_t init_read_secret[kMaxInitSecretLength] = {0};
    Hkdf::HkdfExpand(init_read_secret, kMaxInitSecretLength,
                      init_secret, kMaxInitSecretLength,
                      read_label, read_label_len, digest);
    // ... 对称地派生 write secret，然后安装到加密器中
}
```

注意 `is_server` 这个标志位——它控制着读写方向的翻转。服务端读的是客户端写的，客户端读的是服务端写的。双方用同一套派生逻辑、同一组输入，只是读写方向互换，就各自拿到了一对能互相解密的密钥。

这里有一个细节必须说清楚：Initial Salt 并不是一成不变的。QUIC v1（RFC 9001）用的 Initial Salt 是 `0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`，而 QUIC v2（RFC 9369）的盐是 `0x0dede3def700a6db819381be6e269dcbf9bd2ed9`。quicX 在 `src/quic/crypto/type.h` 里把两个版本的 Salt 都定义为编译期常量（`kInitialSaltV1` / `kInitialSaltV2`），并通过 `GetInitialSalt(version)` 按版本号选择。这个 Salt 的存在意义，是在协议层面给 Initial Secret 做一个版本隔离——不同的 QUIC 版本有不同的起点，避免不同版本之间产生密钥混淆。

更重要的是，**Initial Secret 不是用来保护最终的业务数据的**。它只是握手的第一把引线——它的使命是把第一组 TLS 握手消息安全送达，然后立刻把舞台交给更高一级的密钥（Handshake Secret、1-RTT Secret）。Initial Secret 的生命周期很短，通常只保护 Initial Packet 这几 KB 的数据，之后就会被丢弃。

理解了这一层，你会发现 Initial Secret 的设计哲学其实非常务实：**QUIC 不追求第一步完美，只追求第一步能迈出去**。这是一笔精心计算过的交易——我用一点安全性上的"灰色空间"，换取握手启动能力的飞跃。

---

## 7.3 第一层外壳：第一个包为什么仍然值得加密

你可能会问：Initial Secret 的推导过程既然是公开的，那 Initial Packet 的加密岂不是形同虚设？任何中间人都知道 DCID、知道 Initial Salt、知道派生算法，他为什么不自己也算一遍，然后把包解密？

这个问题值得认真回答，因为它关系到 QUIC 到底在哪个层面保护了握手消息。

首先，**Initial 加密防的不是知道算法的人，而是不知道 DCID 的人**。Initial Packet 的 Header 有一部分是受保护的——特别是 Packet Number 和负载。但 Header 里的关键字段（比如 DCID、Version）确实是明文传输的，因为路由需要这些信息。问题在于：中间人即使看到了 DCID，他能做的事情也极其有限。

其次，**Initial 加密解决的真正问题不是"窃听"，而是"伪装"**。在 TCP + TLS 的世界里，中间人可以做很多事情：伪造 TCP 包触发重传、伪造 TLS 握手消息劫持会话、甚至把某些 TLS 记录类型丢弃来阻断握手。QUIC 把加密嵌入传输层之后，第一个好处就是——**所有握手消息都被包裹在加密外壳里，中间人无法辨认、也无法伪造**。一个 Initial Packet 从客户端发出来，中间人只能看到一团加了密的字节流，他既没办法把它拆开来看里面是什么，也没本事伪造一个能被服务端接受的 Initial Packet。

第三，Initial 加密还有一层常被忽视的价值——**它保护了 TLS 握手的协商面**。ClientHello 里面虽然没有最终的业务秘密，但包含着密码套件偏好、扩展列表、Server Name Indication（SNI）等敏感协商信息。如果这些内容暴露在明文里，中间人可以轻易推断出客户端正在访问哪个域名、偏好什么加密算法，甚至据此做针对性的流量干扰。Initial 加密把整个握手过程包裹起来，让中间人彻底沦为"瞎子"。

当然，我们也要诚实地承认 Initial 加密的边界——**它不提供前向安全性，不防御主动的中间人攻击，也不保护最终的应用数据**。Initial Secret 派生自公开信息这一点，决定了它无法抵抗"记录并重放"攻击。一个有足够能力的主动中间人（MITM），如果能在 TLS 握手阶段就介入，还是有可能通过其他手段来伪造身份。

QUIC 用 Initial Secret 换来的，是一个可以立刻开始加密握手的可能性。剩下的安全级别提升，交给后续的 Handshake 密钥和 1-RTT 密钥去完成——每一轮密钥都会比前一轮更安全，最终达到 TLS 1.3 的完整安全强度。

---

## 7.4 握手的专用河道：为什么 TLS 消息不走普通 Stream

如果说 Initial Secret 是"第一把火"，那 **CRYPTO Frame** 就是把火种输送过去的专用河道。

在 QUIC 里，有一个很容易让人混淆的概念：TLS 握手消息看起来明明像是"流数据"——它们是一段一段的字节，有先后顺序，可以累积发送——那为什么不直接用普通的 STREAM Frame 来传输？

答案藏在一个容易被忽视的细节里：**TLS 握手消息需要的能力，和普通应用数据需要的能力，完全不是一回事**。

普通的 STREAM Frame 有一个 `Stream ID` 字段，用来标识这条数据属于哪条 Stream。在 HTTP/3 over QUIC 的世界里，不同的 Stream 承载不同的 HTTP 请求/响应。但 TLS 握手消息不属于任何一条 Stream——它不属于任何具体的 HTTP 请求，也不是应用数据。它是连接层面的"元数据"，是服务于整个连接的加密协商过程。

这就是 CRYPTO Frame 和 STREAM Frame 的根本区别：

- **STREAM Frame** 属于某条 Stream，有 Stream ID，用来传输应用数据
- **CRYPTO Frame** 不属于任何 Stream，没有 Stream ID，只有 Offset 和 Data，用来传输加密层的握手消息

没有 Stream ID 意味着什么？意味着 CRYPTO Frame 不占用任何应用 Stream 的流控窗口——握手消息的传输不受应用层流量控制的约束。这太重要了。如果握手消息必须和应用数据抢同一套流控资源，那万一应用数据把窗口撑爆了，握手消息可能也跟着卡住——这在 TCP + TLS 的世界里是不可接受的，在 QUIC 里更不能接受。

更重要的是，**CRYPTO Frame 的重组必须完全独立于普通 Stream 的体系**。STREAM Frame 当然也要处理乱序到达和重组——QUIC 的每条 Stream 都有自己的 Offset，网络上照样可能乱序。但两者的关键区别在于：STREAM Frame 的重组发生在 Stream 层面，受到连接级和流级流控窗口的约束；而 CRYPTO Frame 的重组必须脱离这套流控体系，因为**握手消息的送达优先级高于一切**。TLS 要求握手消息必须按照严格的顺序被 TLS 层消费，中间不能有任何缺口。一个 CRYPTO Frame 丢了，后续的 CRYPTO Frame 必须等丢的那个被重传并成功接收，才能一起交付给 TLS。

既然 CRYPTO Frame 没有 Stream ID，它就不属于任何一条 QUIC Stream，自然也无法复用 `StreamManager` 里已有的那套按 Stream ID 索引的缓冲和重组机制。它需要一个独立的承载模块来完成这件事——在 quicX 里，这个模块就是 **CryptoStream**。

---

## 7.5 暗河入场：CryptoStream 如何托住握手数据

TLS 握手消息在 QUIC 的世界里，走的是一条看不见的"暗河"。

当客户端发送一个 ClientHello 时，这个消息可能被切分成多个 CRYPTO Frame——比如第一个 Frame 载着 TLS 记录的头几个字节，第二个 Frame 载着后续的密钥交换参数。这些 Frame 可能在网络上被搞乱顺序，也可能有一部分丢包需要重传。但 TLS 1.3 的状态机要求，握手消息必须按顺序被交付——TLS 层不可能跳过前 100 个字节，直接处理第 101 个字节。

解决方案是：在 CRYPTO Frame 和 TLS 层之间，插入一个缓冲与重组层——也就是 **CryptoStream**。

需要先说清楚一件事：CryptoStream 的乱序重组逻辑本身并没有什么特别的。如果你看过 quicX 里普通 `RecvStream` 的 `OnStreamFrame()` 实现，就会发现两者几乎是一个模子刻出来的——都是维护一个"期望的下一个偏移量"（`except_offset_` / `next_read_offset_`），到了就写入缓冲区，没到就存进 `out_order_frame_` 映射表等着。这套"对上了就消化、对不上就暂存"的模式，是 QUIC 所有基于 Offset 的有序交付的通用做法。

CryptoStream 真正独特的地方在别处：

1. **按加密级别分层**。一条普通 Stream 只需要一个偏移量和一个缓冲区，但 CryptoStream 要为 Initial、Handshake、Application 三个加密级别各维护一套独立的状态。同一时刻，可能 Initial 级别的握手消息还在重组，Handshake 级别的握手消息已经开始到达——它们互不干扰，各走各的。

2. **不受流控约束**。普通 Stream 的接收侧受到连接级和流级流控窗口的限制，而 CryptoStream 完全独立于这套流控体系。握手消息的送达不能因为应用数据把窗口吃满了就被卡住。

3. **没有 Stream ID，不在 StreamManager 的管辖范围内**。它由 `ConnectionCrypto` 直接持有和调度，而不是像普通 Stream 那样通过 Stream ID 在 `StreamManager` 里索引。

在 quicX 的实现里，`ConnectionCrypto` 和 `CryptoStream` 分别对应"密钥管理"和"数据搬运"两件事。`ConnectionCrypto` 是连接级别的加密管理器，同时实现了 TLS 回调接口（`TlsHandlerInterface`）。当 TLS 层通过 `SetReadSecret` / `SetWriteSecret` 回调告知"某个加密级别的密钥已就绪"时，`ConnectionCrypto` 会创建对应的加密器并安装密钥。当连接层收到一个 CRYPTO Frame 时，`ConnectionCrypto` 给它标上加密级别，然后转交给 `CryptoStream`；`CryptoStream` 完成重组后，通过 `recv_cb_` 回调把连续的字节段交还给 TLS。

来看 quicX 中 `CryptoStream::OnCryptoFrame()` 的结构（`src/quic/stream/crypto_stream.cpp`）：

```cpp
void CryptoStream::OnCryptoFrame(std::shared_ptr<IFrame> frame) {
    auto crypto_frame = std::dynamic_pointer_cast<CryptoFrame>(frame);
    uint8_t level = crypto_frame->GetEncryptionLevel();

    if (crypto_frame->GetOffset() == next_read_offset_[level]) {
        // 偏移量对上了，写入对应加密级别的缓冲区
        read_buffers_[level]->Write(crypto_frame->GetData(),
                                     crypto_frame->GetLength());
        next_read_offset_[level] += crypto_frame->GetLength();

        // 扫描乱序缓存，消化后续已就位的帧
        auto& out_order = out_order_frame_[level];
        while (true) {
            auto iter = out_order.find(next_read_offset_[level]);
            if (iter == out_order.end()) break;
            crypto_frame = std::dynamic_pointer_cast<CryptoFrame>(iter->second);
            read_buffers_[level]->Write(crypto_frame->GetData(),
                                         crypto_frame->GetLength());
            next_read_offset_[level] += crypto_frame->GetLength();
            out_order.erase(iter);
        }

        // 交付给 TLS 层
        if (recv_cb_) {
            recv_cb_(read_buffers_[level], 0, level);
        }
    } else {
        // 偏移量对不上，暂存等待
        out_order_frame_[level][crypto_frame->GetOffset()] = crypto_frame;
    }
}
```

对比一下普通 `RecvStream::OnStreamFrame()` 的核心路径——`except_offset_` 对应 `next_read_offset_[level]`，同样的 `out_order_frame_` 扫描循环——你会发现重组逻辑几乎一字不差。唯一的结构性差异就是那个 `[level]` 下标：CryptoStream 为每个加密级别维护独立的偏移量、缓冲区和乱序缓存，而普通 Stream 只需要一套。

---

## 7.6 两个设计决策，一个起步闭环

回头看这一章拆开的两件事，其实是两个独立的设计决策。

第一个决策是 **接受一把"不够安全"的密钥**。Initial Secret 从公开信息派生，任何能抓包的人理论上都能算出来。QUIC 的设计者清楚这一点，但他们也清楚另一件事：如果非要等到密钥完美才开始加密，那第一个包就永远发不出去。Initial Secret 不追求坚不可摧，它只需要撑过握手的头几毫秒——等 TLS 完成协商，Handshake 密钥和 1-RTT 密钥就会接手，把安全性一级一级提到 TLS 1.3 的完整标准。

第二个决策是 **给握手消息修一条专用通道**。CRYPTO Frame 去掉了 Stream ID，脱离了流控体系，而 CryptoStream 为每个加密级别维护独立的缓冲状态。这些设计看起来像是在重复造轮子——普通 Stream 的乱序重组逻辑明明可以复用——但它们解决的是一个结构性问题：握手消息不能被当作普通应用数据来调度，因为它们的优先级和生命周期都跟应用数据完全不同。

这两个决策合在一起，构成了 QUIC 握手的起步闭环：Initial Secret 让第一个包能加密上路，CRYPTO Frame 让握手消息能可靠送达，两者配合让 QUIC 可以在一个 RTT 内完成从"陌生人"到"加密通信"的跨越。
