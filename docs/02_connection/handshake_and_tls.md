# 8. 破冰之握：连接建立与 TLS 融合

QUIC 需要 TLS 的密钥协商能力，但不想要 TLS 的传输外壳。这件事说起来只有一句话，做起来却要动一场大手术——把一个原本自给自足的协议拆开，只留下密钥协商的心脏，把承载、分片、加密封装这些器官全部摘掉，再用 QUIC 自己的零件重新接上。手术刀落在哪里、缝合线走什么路径，就是本章要讲的事。

---

## 8.1 两套世界不能简单叠加：为什么 TCP + TLS 的老办法不适合 QUIC

我们已经知道 QUIC 把加密嵌进了传输层，也知道 TLS Record 被抛弃了。但"嵌入"和"抛弃"这两个词实在太轻飘——它们没有回答一个更尖锐的问题：**到底是 TLS 的哪些东西被留下了，哪些被拿走了，以及为什么非拿不可？**

把 TLS 原封不动地套到 QUIC 上，三个地方会撞车。

**第一，分片撞车**。TLS Record 有自己的分片机制——一条握手消息可能比一个 TCP Segment 大，需要拆开。但在 QUIC 这边，Packet 本身就是分片单位，而且 QUIC 的 Packet 保护（Header Protection + Payload Protection）已经内嵌了加密封装。再套一层 TLS Record，等于在已经封好的信封外面再套一层信封。

**第二，类型系统撞车**。TLS Record 用类型字段来区分握手消息（Handshake）和应用数据（ApplicationData）。但在 QUIC 里，这个区分已经由 Frame 类型完成了——CRYPTO Frame 承载握手消息，STREAM Frame 承载应用数据。两套独立的类型系统同时工作，增加复杂度却不增加价值。

**第三，也是最致命的一个——可靠性语义不兼容**。TLS 假设底下是一条可靠的、按序的字节流，TCP 恰好满足这个假设。但 QUIC 的可靠传输是面向 Frame 语义的，不是面向字节流的。TLS 继续假设底下有字节流，就没法直接嫁接。

但 QUIC 仍然需要 TLS 最核心的那些能力：**(EC)DHE 密钥交换**、**X.509 证书校验**、**HKDF 密钥派生**。TLS 1.3 花了多年时间打磨出的安全模型——前向安全性、零泄露设计、简洁的密钥层次——QUIC 没有理由自己重新造一遍。

所以 QUIC 做了一个非常务实的选择：**把 TLS 拆开，只取它最核心的密钥协商能力，然后把承载、分片、加密封装这些"传输层该做的事"从 TLS 里抽出来，交给 QUIC 自己**。

这就是为什么我们说 QUIC"使用了 TLS 1.3"，但不是"把 TLS 套在 UDP 之上"。TLS 的握手逻辑被嵌进了 QUIC 的 CRYPTO Frame 流里，TLS 派生的密钥被安装到 QUIC 的 Packet 保护机制里，而 TLS Record 层则被彻底抛弃。分层依然存在，但边界已经被重画了。

---

## 8.2 三重门：Initial、Handshake、Application 三个加密阶段如何接力

如果说 QUIC 的握手是一出三幕戏，那 **Initial、Handshake、Application** 就是这三幕戏的名字。每一幕都有自己专属的密钥，每一幕的任务都不同。

**第一幕：Initial 阶段**——这是第 7 章已经讲过的内容。客户端用 Initial Secret 保护第一个 Initial Packet，服务端用同样的 Initial Secret 解密并回复。这个阶段的任务只有一个：把第一组握手消息安全送达，点燃握手的火种。

但 Initial 阶段有个天然的局限：Initial Secret 是从公开信息（DCID + Initial Salt）派生出来的，它不提供前向安全性——如果有人记录了这次握手的所有 Initial Packet，理论上可以在事后破解。这在短期场景下可以接受，但显然不能用来保护长期的应用数据。

这就引出了 **第二幕：Handshake 阶段**。当客户端收到 ServerHello 之后，双方各自用 ClientHello 和 ServerHello 中携带的 (EC)DHE 参数完成密钥交换，算出一个 **shared secret**。TLS 1.3 的密钥调度以这个 shared secret 为原料，通过 HKDF-Extract 派生出 **Handshake Secret**——注意，Handshake Secret 和 Initial Secret 是两条完全独立的派生链路，前者基于只有通信双方才知道的 DHE 共享密钥，后者基于公开的 DCID。Handshake 阶段的使命，是完成身份验证——双方交换证书、验证 Finished，最终确定 **Application Traffic Secret**（即 1-RTT 密钥）。

**前向安全性从这里开始生效**。因为 Handshake Secret 源自临时 (EC)DHE 密钥交换，即使攻击者记录了全部握手包并在事后拿到了服务端的长期私钥，他也无法还原这次 DHE 产生的 shared secret，自然也无法解密 Handshake 和 Application 阶段的任何数据。前向安全性不是某个"阶段"专门提供的，而是 DHE 密钥交换这个机制天然带来的——只要 DHE 临时私钥在用完后被销毁，这条安全承诺就成立。

**第三幕：Application 阶段**——当握手完成，双方都安装了 1-RTT 密钥之后，连接就进入了稳定的数据传输期。这个阶段不再需要握手消息，所有应用数据都用 1-RTT 密钥保护。

为什么这三个阶段不能混成一团？

答案在于 **加密级别的演进需要清晰可辨**。Initial 阶段用的是最"弱"的密钥，因为它只需要完成"点火"这个最小任务；Handshake 阶段用的是更强的密钥，因为它要完成密钥协商的核心工作；Application 阶段用的是最强的密钥，因为它是连接最常见、最长期的工作状态。

更重要的是，这三个阶段和 QUIC 的包类型有明确的映射关系：Initial Packet 用 Initial Secret 保护，Handshake Packet 用 Handshake Secret 保护，1-RTT Packet（也叫 Short Header Packet）用 Application Traffic Secret 保护。**每一种包类型，都对应着一种特定的加密级别**。这种清晰的映射，让接收端在看到一个包的时候，立刻就知道该用哪把钥匙来解密它。

理解了"三重门"的推进逻辑，你就理解了 QUIC 握手最核心的结构——不是一堆散乱的密钥，而是一条清晰的、逐步升级的加密推进链。

---

## 8.3 一个往返里的手术：1-RTT 握手是怎样被拼出来的

QUIC 经常被宣传为"1-RTT 握手"——只需要一次往返就能完成握手，听起来比 TCP + TLS 的 1.5 + 1 = 2.5 RTT 快了很多。

但"1-RTT 很快"这句话如果不拆开看，很容易让人误以为"QUIC 少做了事"。实际情况恰恰相反：**QUIC 不是少做了事，而是把事排得足够紧凑**。

我们来看看这"一次往返"里到底发生了什么。

**客户端出发**：客户端发出第一个 Initial Packet，里面装着 TLS ClientHello。这个包用 Initial Secret 保护。ClientHello 里包含着客户端的密码套件偏好、密钥交换参数、随机数等等。客户端发完这个包，握手就正式开始了——计时器开始走，客户端开始等服务端的回复。

**服务端接收并回复**：服务端收到客户端的 Initial Packet 之后，用 Initial Secret 解密，拿到 ClientHello。然后服务端开始处理 TLS 握手——生成自己的随机数、选择密码套件、生成密钥交换参数、准备证书……

关键来了：**服务端并不是等到所有 TLS 握手消息都准备完毕之后才回复**。TLS 1.3 的设计允许服务端在一个往返里就完成几乎所有握手工作——ServerHello、证书、验证 Finished，全部可以塞进同一个回复包里。

但这个回复包有点复杂：因为服务端同时要发两种加密级别的数据。Initial 包的回复（ACK 和继续的握手消息）需要用 Initial Secret 保护；但与此同时，服务端已经可以开始用 Handshake Secret 发送 Handshake 级别的数据了。

这就是 QUIC 真正"快"的地方：**Packet Coalescing**。一个 UDP Datagram 里，可以同时装多个不同加密级别的 QUIC Packet——服务端可以把 Initial 包的 ACK 和 Handshake 包塞进同一个 UDP Datagram 里发出去。接收端收到之后，按照顺序一个个拆开：先用 Initial Secret 解密 Initial Packet，再用 Handshake Secret 解密 Handshake Packet。

**客户端收到这个 Datagram 之后，事情还没完**。客户端先从 ServerHello 中提取服务端的 (EC)DHE 参数，算出 shared secret，派生出 Handshake Secret——这把钥匙让它能解密同一个 Datagram 里紧跟着的 Handshake Packet。打开之后，里面是服务端的证书链、CertificateVerify 签名和 Finished 消息。客户端逐一验证：证书是不是可信的？签名能不能通过？Finished 里的摘要对不对得上？

验证全部通过之后，客户端做两件事：发送自己的 Handshake Finished（证明自己也完成了握手），同时安装 1-RTT 密钥。从这一刻起，客户端已经可以用 1-RTT 密钥发送应用数据了——虽然服务端要等收到客户端的 Finished 之后才会确认握手完成。

用一张时序图来看，这"一次往返"里实际发生的事情远比想象中密集：

```
客户端                                              服务端
  │                                                  │
  │  ─── Initial Packet ──────────────────────────>  │
  │      [CRYPTO: ClientHello]                       │
  │      (Initial Secret 保护)                        │
  │                                                  │
  │                                                  │  派生 Handshake Secret
  │                                                  │  (从 DHE shared secret)
  │                                                  │
  │  <── Initial Packet ───────────────────────────  │
  │      [ACK]                                       │
  │  <── Handshake Packet ─────────────────────────  │  ┐
  │      [CRYPTO: ServerHello]                       │  │ Packet Coalescing
  │      [CRYPTO: Certificate]                       │  │ 多个加密级别的包
  │      [CRYPTO: CertificateVerify]                 │  │ 塞进同一个
  │      [CRYPTO: Finished]                          │  │ UDP Datagram
  │      (Handshake Secret 保护)                      │  ┘
  │                                                  │
  │  派生 Handshake Secret                            │
  │  解密证书 → 验证签名 → 校验 Finished               │
  │  派生 Application Traffic Secret (1-RTT 密钥)     │
  │                                                  │
  │  ─── Handshake Packet ─────────────────────────> │
  │      [CRYPTO: Finished]                          │
  │  ─── 1-RTT Packet ────────────────────────────>  │
  │      [STREAM: 应用数据]                           │
  │      (1-RTT 密钥保护)                              │
  │                                                  │
  │                                                  │  验证客户端 Finished
  │                                                  │  握手确认完成
  │                                                  │
  │  <══ 1-RTT Packet ════════════════════════════   │
  │      [STREAM: 应用数据]                           │
  │                                                  │
           总计：1 RTT 之后客户端即可发送应用数据
```

注意图中的关键细节：服务端的回复是一个 **Coalesced Datagram**——Initial ACK 和 Handshake 包被塞进同一个 UDP 报文里。客户端收到后按序拆开，先用 Initial Secret 解 ACK，再用刚派生的 Handshake Secret 解密证书和 Finished。验证通过后，客户端同时发出自己的 Handshake Finished 和第一个 1-RTT 应用数据包——这就是"1-RTT"名字的由来。

这就是为什么 1-RTT 握手看起来"只有一个往返"，但背后其实是多次加密级别的协作：Initial 级别的消息在启动握手，Handshake 级别的消息在完成身份验证，而最终的业务数据通道——Application 级别——在这个往返结束时就可以启用了。

对实现层来说，这种"紧凑排布"提出了很高的要求。发送端需要精确控制哪些数据用哪个级别的密钥保护，哪些数据可以合并到一个 Datagram 里，哪些数据必须等前一个加密级别完成才能发送。**QUIC 的快，不是少做了事，而是把每一件事的顺序都优化到了极致**。

---

## 8.4 握手的翻译官：TLS 与 QUIC 之间到底谁负责什么

说了半天融合，很多人可能会问：**TLS 和 QUIC 到底谁在指挥谁？**

这个问题本身就带了一点误解。QUIC 不是"用 TLS 的 QUIC"，TLS 也不是"被 QUIC 控制的 TLS"。它们之间的关系，更像是一场双向协作——**不是谁驱动谁，而是各自发挥所长，然后在握手这个节点上完美交接**。

**TLS 负责的事情**：
- **握手逻辑**：TLS 决定什么时候该发 ClientHello、什么时候该收 ServerHello、什么时候该互相交换证书、什么时候握手算完成
- **证书校验**：TLS 内置的 X.509 证书验证逻辑，负责检查服务端（和可选的客户端）证书是否有效、是否可信
- **密钥派生**：TLS 的 HKDF 模块负责从各种 Secret（Initial、Handshake、Application）派生出实际的加密密钥和 IV

**QUIC 负责的事情**：
- **承载与分片**：TLS 产生的握手消息（握手记录）会被切分成 CRYPTO Frame，装进 Packet 里发送。QUIC 决定每个 Frame 放多少字节、每个 Packet 装哪些 Frame
- **重传与可靠**：TLS 只需要关心"消息有没有被收到"，不需要关心"丢包了怎么补"——这是 QUIC 的事
- **加密级别调度**：TLS 说"我现在要从 Initial 升级到 Handshake"，QUIC 就切换到对应的密钥，给后续的 Packet 加上对应的保护

这里最关键的理解是：**这不是"TLS 驱动 QUIC"，也不是"QUIC 驱动 TLS"，而是双向协作**。TLS 提供的是"抽象的密钥"，QUIC 负责把这些密钥"落地"到具体的 Packet 保护上。

用一张分层图来看，QUIC 内部的协议分层和 TLS 的嵌入位置是这样的（参考 RFC 9001 Figure 3 & 4）：

```
┌──────────────┬──────────────┐ ┌─────────────┐
│     TLS      │     TLS      │ │    QUIC     │
│  Handshake   │    Alerts    │ │ Applications│
│              │              │ │  (H3, etc.) │
├──────────────┴──────────────┴─┴─────────────┤
│                                             │
│              QUIC Transport                 │
│   (streams, reliability, congestion, etc.)  │
│                                             │
├─────────────────────────────────────────────┤
│                                             │
│          QUIC Packet Protection             │
│                                             │
└─────────────────────────────────────────────┘

TLS 和 QUIC 之间的数据流向：

┌────────────┐                         ┌────────────┐
│            │<── Handshake Messages ──>│            │
│            │<── Validate 0-RTT ──────>│            │
│            │<── 0-RTT Keys ──────────│            │
│    QUIC    │<── Handshake Keys ──────│    TLS     │
│            │<── 1-RTT Keys ─────────│            │
│            │<── Handshake Done ──────│            │
└────────────┘                         └────────────┘
  │         ▲
  │ Protect │ Protected
  ▼         │ Packet
┌────────────┐
│   QUIC     │
│  Packet    │
│ Protection │
└────────────┘
```

上面这张图有两个关键信息。第一，TLS Handshake 和 TLS Alerts 与 QUIC Applications（比如 HTTP/3）是**并排坐在 QUIC Transport 之上**的——TLS 不是"包在 QUIC 外面"，而是嵌在 QUIC 里面，作为 QUIC 的一个内部组件。第二，TLS 向 QUIC 输出的不是加密后的数据，而是**密钥本身**——QUIC 拿到密钥后，自己完成 Packet Protection。这和 TCP + TLS 的模型截然不同：在那个模型里，TLS 既派生密钥又用密钥加密数据；在 QUIC 里，TLS 只派生密钥，加密的活由 QUIC Packet Protection 来干。

具体到工程实现上，BoringSSL（Google 的 TLS 1.3 实现）提供了一套 **SSL_QUIC_METHOD** 接口。要理解这套接口在概念上解决了什么问题，得先想清楚传统 TLS 库是怎么工作的。

在 TCP 的世界里，TLS 库自己控制网络 I/O——它直接调用 `read()` / `write()` 来收发数据。换句话说，TLS 库是"主动推送"模式：我要发握手消息了，我来调 socket 写出去；我要收握手消息了，我来调 socket 读进来。

但在 QUIC 里，这套"push 模型"行不通了。握手消息不走 socket，走的是 CRYPTO Frame；密钥不是 TLS 自己用来加密 Record 的，而是要交给 QUIC 去保护 Packet。TLS 库不能再自己控制网络 I/O，它必须变成一个"被动提供服务"的角色——**QUIC 喂给它握手数据，它产出密钥和握手响应，然后 QUIC 决定怎么发出去**。

`SSL_QUIC_METHOD` 就是实现这个"push 到 pull"转换的接口契约。它是一组回调函数，QUIC 侧注册给 BoringSSL，让 TLS 库在需要的时候"回调"QUIC：

- **`SetReadSecret` / `SetWriteSecret`**：TLS 派生出新密钥时，通过这两个回调通知 QUIC "这是新的读/写密钥，请安装"
- **`AddHandshakeData`**：TLS 产生握手输出时，通过这个回调把数据交给 QUIC，由 QUIC 负责切成 CRYPTO Frame 发送
- **`FlushFlight`**：TLS 告诉 QUIC "这一批握手消息可以发了"
- **`SendAlert`**：出错时通知 QUIC 发送 TLS Alert

理解这个职责边界，比背接口名重要一百倍。**当你知道 TLS 只负责"握手逻辑+密钥派生"，而 QUIC 负责"承载+加密+可靠传输"的时候，整个融合模型就变得清晰了**。

---

## 8.5 quicX 的粘合层：ConnectionCrypto 如何把两套机器接上

协议层面的融合，最终要落到工程实现上。在 quicX 里，这个"粘合层"就是 **ConnectionCrypto**。

如果说 TLS 是一台负责"握手逻辑"的机器，QUIC Packet 处理是另一台负责"可靠传输"的机器，那 ConnectionCrypto 就是连接这两台机器的变速箱——它把 TLS 输出的密钥翻译成 QUIC 能用的 Packet 保护参数，又把 QUIC 收到的 CRYPTO Frame 翻译成 TLS 能消费的握手消息。

先看它的类声明（`src/quic/connection/connection_crypto.h`）：

```cpp
class ConnectionCrypto: public TlsHandlerInterface {
public:
    // ——TLS 回调，由 BoringSSL 通过 SSL_QUIC_METHOD 间接触发——
    virtual void SetReadSecret(SSL* ssl, EncryptionLevel level,
                               const SSL_CIPHER* cipher,
                               const uint8_t* secret, size_t secret_len);
    virtual void SetWriteSecret(SSL* ssl, EncryptionLevel level,
                                const SSL_CIPHER* cipher,
                                const uint8_t* secret, size_t secret_len);
    virtual void WriteMessage(EncryptionLevel level, const uint8_t* data, size_t len);
    virtual void FlushFlight();
    virtual void SendAlert(EncryptionLevel level, uint8_t alert);

    // ——QUIC 侧主动调用——
    void OnCryptoFrame(std::shared_ptr<IFrame> frame);
    bool TriggerKeyUpdate();

private:
    EncryptionLevel cur_encryption_level_;
    std::shared_ptr<CryptoStream> crypto_stream_;
    std::shared_ptr<ICryptographer> cryptographers_[kNumEncryptionLevels]; // 4 个级别
};
```

一个类，两张脸。上半部分是 `TlsHandlerInterface` 的虚函数实现——这些方法不是 quicX 主动调的，而是 BoringSSL 在握手推进过程中通过回调链触发的。下半部分是 QUIC 侧的入口——`OnCryptoFrame` 把收到的握手数据喂给 TLS，`TriggerKeyUpdate` 在长连接期间换钥。

回调链怎么串起来的？看 `TLSConnection`（`src/quic/crypto/tls/tls_connection.cpp`）里的注册：

```cpp
static const SSL_QUIC_METHOD gQuicMethod = {
    TLSConnection::SetReadSecret,   // BoringSSL 派生出读密钥时回调
    TLSConnection::SetWriteSecret,  // BoringSSL 派生出写密钥时回调
    TLSConnection::AddHandshakeData,// BoringSSL 产出握手消息时回调
    TLSConnection::FlushFlight,     // 一批握手消息可以发送时回调
    TLSConnection::SendAlert,       // 出错时回调
};

// Init() 中注册：
SSL_set_quic_method(ssl_.get(), &gQuicMethod);
```

`gQuicMethod` 里的五个静态函数，就是上一节说的"pull 模型"接口。BoringSSL 不碰网络、不碰 Packet，它只通过这五个出口把结果交出来。`TLSConnection` 的静态函数收到回调后，通过 `SSL_get_app_data` 拿回自己的实例指针，再转发给 `handler_`——也就是 `ConnectionCrypto`。

整条链路：**BoringSSL → gQuicMethod 静态回调 → TLSConnection → ConnectionCrypto**。

密钥安装的核心流程，看 `SetReadSecret`（`src/quic/connection/connection_crypto.cpp`）：

```cpp
void ConnectionCrypto::SetReadSecret(
    SSL* ssl, EncryptionLevel level, const SSL_CIPHER* cipher,
    const uint8_t* secret, size_t secret_len) {
    std::shared_ptr<ICryptographer> cryptographer = cryptographers_[level];
    if (cryptographer == nullptr) {
        cryptographer = MakeCryptographer(cipher);  // 按密码套件创建加解密器
        cryptographer->SetVersion(quic_version_);
        cryptographers_[level] = cryptographer;     // 安装到对应级别的槽位
    }
    cur_encryption_level_ = level;                  // 推进当前加密级别
    cryptographer->InstallSecretWithVersion(secret, (uint32_t)secret_len, false, quic_version_);
}
```

四个加密级别（`kInitial`、`kEarlyData`、`kHandshake`、`kApplication`），四个槽位，每次 TLS 派生出新密钥，就往对应槽位装一把新锁。`cur_encryption_level_` 标记当前走到了哪一级——这个状态和连接状态机紧密配合，握手推进到哪一步，加密级别就切换到哪一级。

为什么 quicX 要把 ConnectionCrypto、CryptoStream、连接状态推进解耦成三个独立模块？

因为 **加密级别的切换、握手消息的处理、连接状态的推进，是三个不同维度的问题**。把它们混在一起，只会得到一个巨大的、难以维护的"总指挥"类。把它们拆开，每个模块只专注自己的职责，然后用清晰的消息传递把它们串联起来——这就是 quicX 在工程层面的选择。

---

## 8.6 握手之后，钥匙也不会永远不变：Key Update 在哪里发生

当握手完成，应用数据开始用 1-RTT 密钥稳定传输，很多人会以为密钥就不会再变了。实际上 **Key Update 是 QUIC/TLS 融合模型的自然延伸**——它发生在连接已经成熟运行之后，而不是把连接重新拉回握手期。

想象一下：你有一扇门，钥匙是 1-RTT 密钥。通常情况下，这扇门一直用同一把钥匙就能正常开关。但时间长了，你总会想——万一这把钥匙被复制了呢？万一有人通过长期观察发现了钥匙的规律呢？

Key Update 就是来解决这个问题的。它做的事情很简单：**在不中断连接的前提下，把 1-RTT 密钥平滑切换到新一代的密钥**。

为什么说它是"自然延伸"而不是"重新握手"？

因为 Key Update 完全发生在 Application 级别之内。它不需要再走一遍 Initial → Handshake → Application 的完整升级路径，不需要再交换证书，不需要再验证身份。RFC 9001 §6 甚至明确禁止在 QUIC 里发送 TLS 的 `KeyUpdate` 消息——**QUIC 的 Key Update 根本不经过 TLS 握手层，而是完全由 QUIC 自己在传输层完成的**。

具体来说，新密钥的派生非常直接：

```
next_secret = HKDF-Expand-Label(current_secret, "quic ku", "", hash_len)
```

从当前的 Application Traffic Secret 出发，用 `"quic ku"` 作为标签，通过一次 HKDF-Expand-Label 就能算出下一代 secret，再从新 secret 派生出新的加密密钥和 IV。没有握手消息来回、没有证书交换——一次哈希运算就完成了换代。

那接收端怎么知道发送端换了钥匙？

答案藏在 Short Header（1-RTT Packet）里的一个 1-bit 标志位：**Key Phase bit**。发起方翻转这个 bit（从 0 变 1，或从 1 变 0），然后用新密钥加密后续的包。接收方看到 Key Phase 发生变化，就知道对端已经换了钥匙，于是自行计算新密钥来解密——不需要任何显式的"确认"消息。接收方随后也会更新自己的发送密钥，跟随翻转 Key Phase。

在这个过渡窗口里，旧密钥还会保留一段时间。因为网络中可能还有用旧密钥加密的在途包，接收方需要能够同时用新旧两代密钥来解密，直到确认所有旧包都已到达或超时。

在 quicX 里，`KeyUpdateTrigger`（`src/quic/connection/key_update_trigger.h`）负责决定"什么时候该换"——它同时监控发送字节量和包号间隔，任一指标越过阈值就触发更新。而 `ConnectionCrypto::TriggerKeyUpdate()` 负责实际的换钥动作：直接调用 `cryptographer->KeyUpdateWithVersion()`，在 Application 级别的 cryptographer 上原地完成密钥轮换，整个过程不涉及 TLS 库的任何调用。

```cpp
// src/quic/connection/connection_crypto.cpp
bool ConnectionCrypto::TriggerKeyUpdate() {
    auto cryptographer = cryptographers_[kApplication];
    if (!cryptographer) { return false; }
    // 先更新写密钥（出站流量），再更新读密钥（入站流量）
    auto result = cryptographer->KeyUpdateWithVersion(nullptr, 0, true, quic_version_);
    if (result != ICryptographer::Result::kOk) { return false; }
    result = cryptographer->KeyUpdateWithVersion(nullptr, 0, false, quic_version_);
    return result == ICryptographer::Result::kOk;
}
```

Key Phase bit 则定义在 `ShortHeaderFlag`（`src/quic/packet/header/header_flag.h`）里——仅仅 1 bit，却承载了整个 Key Update 的信令职责：

```cpp
struct ShortHeaderFlag {
    uint8_t packet_number_length_ : 2;
    uint8_t key_phase_ : 1;            // ← 就是这 1 bit
    uint8_t reserved_bits_ : 2;
    uint8_t spin_bit_ : 1;
    uint8_t fix_bit_ : 1;
    uint8_t header_form_ : 1;
};
```

这正是 QUIC/TLS 融合模型的一个精彩缩影：密钥的演化不是"一次性的事件"，而是一个"持续的过程"。从 Initial 点火，到 Handshake 升级，到 Application 稳定运行，再到 Key Update 平滑轮换——整个密钥生命周期都被纳入了同一个设计框架。而这一切，TLS 库甚至不需要知情。

---

## 8.7 看起来像握手，其实是在重画分层

如果只能从本章带走一句话，那就是这句：**QUIC 不是在"使用 TLS"，而是在重画传输层和安全层的边界**。

在 TCP 的世界里，传输层和安全层是两栋独立的楼——TCP 管可靠，TLS 管加密，各自有自己的分片、有自己的头部、有自己的状态机。它们通过一条字节流管道连接，彼此不需要知道对方的内部细节。

QUIC 把这两栋楼拆了，重新盖成了一栋。TLS 的握手逻辑被嵌进了 CRYPTO Frame 流里，TLS 派生的密钥被直接安装到 Packet 保护模块上，TLS Record 层被 QUIC 的 Frame + Packet 封装彻底取代。这不是拼接，是融合——代价是实现复杂度的陡增，收益是 1-RTT 握手和 Key Update 这种在旧架构下根本不可能的东西。

quicX 的 `ConnectionCrypto` 就是这场融合在 C++ 里的一个切面：一个类，同时实现着 TLS 回调接口和 QUIC 密钥管理接口，把两个原本互不相识的系统缝在一起。它不优雅，但它诚实——因为协议本身要求的就是这种深度的交织，而不是隔着一条字节流管道的客气。

---
