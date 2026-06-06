# 9. 零等待的奇迹：0-RTT 与会话恢复

1-RTT 握手已经把建连延迟压到了一次往返，但"一次往返"仍然是一次等待——客户端发出 ClientHello 之后必须干等服务端回复，然后才能发送第一字节的业务数据。在 WiFi 上这个等待可能只有十几毫秒，但在地铁里切到 4G 信号的手机上，它可能是 100 毫秒甚至 200 毫秒。QUIC 的设计者想把这最后一个"等"也挤掉——让客户端在握手还没完成的时候就把应用数据先发出去。这个想法听起来像是白捡的加速，但天下没有免费的午餐：你敢抢跑，就得承受抢跑的代价。

---

## 9.1 再快一步：为什么 1-RTT 还不是终点

想想你在手机上打开一个搜索页面的场景。你每次点击，App 都要和服务器重新建立连接。1-RTT 握手意味着：你点下搜索按钮后，得等客户端发一个包、服务端回一个包，双方把加密参数定稿，然后——应用数据才能真正开始流动。

**1-RTT 虽然已经很快，但它本质上还是一种"等待"——客户端必须等服务端点头认可，才能开始发送真正的业务数据。** 这最后一个"等"字，在高延迟网络下显得格外刺眼。

于是 QUIC 往前又迈了一步：**能不能让客户端在握手还没完成的时候，就把应用数据先发出去？**

这就是 0-RTT 的动机。它不是凭空出现的性能优化，而是对真实时延焦虑的继续回应。QUIC 想消灭的，不只是 TCP 三次握手那 1.5 个 RTT，还有 1-RTT 握手最后那一个等待点。

但这立刻引出了一连串问题：客户端凭什么敢在握手完成前就发数据？服务端在没有完成握手的情况下，凭什么敢接受这些数据？这种"抢跑"机制安全吗？

答案藏在"会话恢复"里。

---

## 9.2 把上一次连接带进下一次连接：会话恢复依赖什么

要理解 0-RTT 是怎么发生的，我们得先回到上一次连接结束的时候。

当你第一次访问一个 HTTPS 网站时，双方走的是完整的 1-RTT 握手。但在握手即将完成的那一刻，服务端会做一件额外的事——它会给客户端发一个叫做 **Session Ticket**（会话票据）的东西。这个票据本质上是一把"临时钥匙"，它把服务器端记住的密码学上下文——比如双方协商好的加密算法、密钥材料、会话状态——封装加密后，交给客户端保管。

客户端把这个票据存下来。下一次它再来访问同一个服务器时，情况就完全不同了：

客户端不再需要等服务端回复 ServerHello 才能确定加密参数，而是可以直接使用上次握手留下的 **Pre-Shared Key**（预共享密钥，简称 PSK）来加密数据。这个 PSK 就是 Session Ticket 里解密出来的密钥材料。

所以 0-RTT 的本质，不是"跳过握手"，而是**"借用上一次连接的信任残影"**。服务端上一次已经验证过客户端的身份、协商好了加密参数、建立了密码学上下文——这些"信任的痕迹"被封装进票据，客户端下次来的时候直接拎着这个残影就能上场。

但"信任残影"不仅仅是一把密钥。RFC 9000 §7.4.1 有一条常被忽略但至关重要的要求：**客户端在尝试 0-RTT 时，必须使用上一次连接中服务端通告的传输参数**——包括 `initial_max_data`、`initial_max_streams_bidi`、`initial_max_stream_data_bidi_local` 等流控参数。道理很简单：0-RTT 数据在握手完成前就发出去了，此时新连接的传输参数还没有协商完成。如果客户端不记住上一次的流控窗口，它根本不知道自己能发多少数据、能打开多少条流。这些"记忆的传输参数"和 PSK 一起，构成了 0-RTT 能够运作的完整前提。

这里还有一个关键前提：**0-RTT 天然只适合"曾经见过面"的双方**。第一次访问时，双方完全陌生，没有任何共享密钥可用，0-RTT 就无从谈起。只有当客户端和服务端已经完成过至少一次成功的握手，才会有 Session Ticket 可以复用。

QUIC 的会话恢复与 TLS 1.3 深度绑定，原因就在这里。TLS 1.3 定义了完整的 Session Ticket 和 PSK 机制，QUIC 直接借用了这层能力，把 TLS 的会话恢复无缝嵌入了自己的握手流程。客户端在发送 ClientHello 的同时，就可以带上上次收到的 Session Ticket 和记忆的传输参数，请求服务端认可自己使用 0-RTT 早期数据。

这就是 0-RTT 发生的"前提"——不是凭空加速，而是建立在"前缘记忆"之上：一把从上次连接继承的密钥，加上一组从上次连接记住的流控窗口。

---

## 9.3 早到的数据：0-RTT 到底提前发送了什么

现在我们知道了 0-RTT 发生的条件。接下来要回答一个问题：0-RTT 状态下，客户端提前发送的到底是什么？

在正常的 1-RTT 握手里，客户端发送的第一个包是 ClientHello，服务端回复 ServerHello，然后双方交换加密参数，最后才进入 Application 数据阶段。这里面的"等"在于：应用数据必须等到 1-RTT 握手完成之后才能发送。

但在 0-RTT 场景里，客户端可以在发送 ClientHello 的同时——甚至在收到服务端的任何回复之前——就把应用数据装进 Packet 发出去。这些数据用的是 0-RTT 密钥（从 PSK 派生出来的），和正常握手的 1-RTT 密钥是不同的加密级别。

这里有一个协议细节特别关键：**0-RTT 包和 1-RTT 包使用的是不同的密钥**。0-RTT 密钥是从 PSK 派生的，它只用来保护早期数据。而 1-RTT 密钥是完整握手后才生成的，它保护的是后续所有的应用数据。这两个加密级别是并行的、独立的。

用一张时序图来看 0-RTT 的完整发送过程：

```
客户端（持有上次的 Session Ticket + 记忆传输参数）              服务端
  │                                                          │
  │  ─── Initial Packet ──────────────────────────────────>  │
  │      [CRYPTO: ClientHello + PSK extension]               │
  │      (Initial Secret 保护)                                │
  │                                                          │
  │  ─── 0-RTT Packet ───────────────────────────────────>   │  ← 不等回复，
  │      [STREAM: 应用数据 (GET /search?q=...)]              │    直接发送！
  │      (0-RTT 密钥保护，从 PSK 派生)                        │
  │                                                          │
  │                                                          │  验证 PSK → 派生 0-RTT 读密钥
  │                                                          │  解密 0-RTT 数据 → 交给应用层
  │                                                          │
  │  <── Initial + Handshake Packet (Coalesced) ───────────  │
  │      [ServerHello + Certificate + Finished]              │
  │                                                          │
  │  验证证书 → 派生 1-RTT 密钥                                │
  │                                                          │
  │  ─── Handshake Finished ──────────────────────────────>  │
  │  ─── 1-RTT Packet ───────────────────────────────────>   │
  │      [STREAM: 后续应用数据]                               │
  │      (1-RTT 密钥保护)                                     │
  │                                                          │
          ↑ 0-RTT 数据在第一个 RTT 完成之前就已到达服务端
```

注意图中的关键动作：客户端在发出 Initial Packet（携带 ClientHello）之后，紧接着就用 0-RTT 密钥发出应用数据包——**不等服务端的任何回复**。这两个包甚至可以通过 Packet Coalescing 塞进同一个 UDP Datagram。服务端收到后，先用 Initial Secret 解密 ClientHello，验证 PSK 有效后派生 0-RTT 读密钥，再用它解密紧随其后的 0-RTT 数据。

服务端收到这些 0-RTT 包之后，有两个选择：

- **接受 0-RTT 数据**：服务端用对应的 0-RTT 密钥解密数据，把它们交给上层应用。握手继续走剩下的流程，1-RTT 密钥生成后，连接平滑切换到 1-RTT 加密级别。
- **拒绝 0-RTT 数据**：服务端不认可这个 PSK，或者出于安全策略选择不接受 0-RTT，它会忽略这些早期数据，只处理正常的握手包。客户端检测到 0-RTT 被拒后，不是简单地"降级"——RFC 9001 §4.6.2 要求客户端**重置所有 0-RTT 阶段创建的流的状态**，然后用 1-RTT 密钥重新发送这些数据。

0-RTT 成功时，它节省的到底是哪个等待点？**它让客户端可以把第一个应用数据的发送时间，从"等完整个 1-RTT 握手"提前到"ClientHello 发出去的那一刻"**。在高延迟网络下，这个提前量就是一整个 RTT——用户点下搜索按钮的瞬间，请求数据就已经在路上了。

从协议的角度看，0-RTT 不是一个独立的"模式"，而是 1-RTT 握手的一个"加速通道"。它看似是协议特性，本质上却直接影响用户体验——用户点下按钮的那一刻，数据就已经在路上了，而不是干等着握手完成。

---

## 9.4 抢跑的代价：可重放风险为什么无法凭空消失

0-RTT 这么快，听起来像是白捡的性能优化。但 QUIC 的设计者非常清楚：**天下没有免费的午餐。**

0-RTT 提前发送的应用数据，有一个先天性的安全缺陷——**它无法获得和 1-RTT 完全相同的安全属性**。具体来说，0-RTT 数据缺乏前向安全性（forward secrecy）。原因不难理解：1-RTT 密钥之所以拥有前向安全性，是因为它依赖于**本次连接中新鲜的 (EC)DHE 密钥交换**——每次握手都会生成一对临时密钥，用完即销毁。但 0-RTT 数据在发送时，本次 DHE 交换还没有完成，它的密钥只能来自上一次连接留下的 PSK。如果这个 PSK 泄露——比如攻击者攻破了存储 Session Ticket 加密密钥的服务端——那么所有用该 PSK 保护的 0-RTT 数据都可以被追溯解密。

但比前向安全性更核心的问题是**可重放攻击**（replay attack）。

想象这样一个场景：你在用一个银行 App 进行转账。你发起了一笔 100 元的转账请求，这个请求被装进 0-RTT 包发给了服务器。正常情况下，服务器收到了你的请求，处理了转账，100 元转出去了。

但如果有一个恶意攻击者，他正好在网络中嗅探到了这个 0-RTT 包会怎么样？他能不能把这个包复制下来，一模一样地再发一遍？

在 0-RTT 的机制下，答案是**有可能**。因为 0-RTT 数据使用的密钥是"老密钥"——它是从上次会话继承过来的，不是这一次的全新协商。服务端在处理 0-RTT 数据时，无法像处理 1-RTT 数据那样，确认"这个数据确实是这一次新发出来的"。

这就是 0-RTT 最大的安全代价：**它无法防止重放**。一个被截获的 0-RTT 包，攻击者可以在任何时候重新发送，服务端会把它当作合法的早期数据来处理。

正因为这个原因，**0-RTT 不是所有请求都适合进入的通道**。协议层和应用层在这里有明确的边界责任：

- **协议层**（QUIC/TLS）明确告知应用层：0-RTT 数据无法防重放，应用需要自己判断哪些请求可以走 0-RTT。
- **应用层**（HTTP）通过一些约定俗成的规则来处理这个问题：GET 请求通常可以进入 0-RTT（幂等），但 POST 请求（可能修改服务端状态）通常不走 0-RTT。HTTP/3 更是明确规定：0-RTT 只能用于幂等请求。

QUIC 在这里并没有"完美解决"可重放问题——它做了一个权衡：**我用安全边界来换时延优势，但这个边界在哪里，我明确告诉你，你自己判断。** 这是一种诚实的协议设计：不回避代价，而是把代价讲清楚，让上层去做明智的选择。

---

## 9.5 quicX 的恢复路径：session cache、early data 与接受策略

理解了 0-RTT 的协议动机和安全边界，我们现在来看看 quicX 是怎么在工程层面实现这套机制的。0-RTT 的工程落地涉及三个核心问题：上一次的"信任残影"存在哪里、怎么触发 0-RTT 发送、以及发送调度是如何工作的。

### 记忆的容器：SessionCache

quicX 的 `SessionCache`（`src/quic/connection/session_cache.h`）是一个全局单例，负责存储和检索 Session Ticket 与记忆的传输参数。它的设计有两层：**内存中的 LRU 缓存**用于快速查找，**磁盘上的 `.session` 文件**用于跨进程持久化。

```cpp
class SessionCache: public common::Singleton<SessionCache> {
private:
    // 内存层：server_name → SessionInfo（元数据），session_der 存在磁盘上
    std::unordered_map<std::string, SessionInfo> sessions_cache_;

    // LRU 淘汰：最近使用的在 front，最久未用的在 back
    std::list<std::string> lru_list_;
    std::unordered_map<std::string, std::list<std::string>::iterator> lru_map_;

    uint32_t max_cache_size_;  // 默认 100 条
};
```

`SessionInfo` 不只是 PSK 的包装——它还携带了 RFC 9000 §7.4.1 要求的记忆传输参数：

```cpp
struct SessionInfo {
    uint64_t creation_time;     // 会话创建时间
    uint32_t timeout;           // 超时时间
    bool early_data_capable;    // 是否支持 0-RTT

    // RFC 9000 §7.4.1：记忆的传输参数
    bool has_transport_params = false;
    uint32_t initial_max_data = 0;
    uint32_t initial_max_streams_bidi = 0;
    uint32_t initial_max_streams_uni = 0;
    uint32_t initial_max_stream_data_bidi_local = 0;
    uint32_t initial_max_stream_data_bidi_remote = 0;
    uint32_t initial_max_stream_data_uni = 0;
    uint32_t active_connection_id_limit = 0;
};
```

磁盘文件用一个 4 字节 Magic（`0x53455353`，即 ASCII "SESS"）和版本号开头，Version 2 新增了传输参数的序列化。每 20 分钟惰性清理一次过期 session，缓存满时从 LRU 尾部淘汰。

### 连接建立时的恢复路径

当客户端发起 0-RTT 连接时，`ClientConnection::Dial()` 做的事远不止"设置 PSK"这么简单（`src/quic/connection/connection_client.cpp`）：

```cpp
// 1. 从 SessionCache 取出 session + 记忆的传输参数
SessionInfo cached_session_info;
std::string session_der;
SessionCache::Instance().GetSessionWithInfo(session_key, session_der, cached_session_info);

// 2. 把 DER 编码的 session 设置到 TLS 层（启用 0-RTT）
tls_conn->SetSession(reinterpret_cast<const uint8_t*>(session_der.data()), session_der.size());

// 3. 用记忆的传输参数预初始化流控制器
if (cached_session_info.has_transport_params && cached_session_info.early_data_capable) {
    TransportParam remembered_tp;
    QuicTransportParams remembered_qtp;
    remembered_qtp.initial_max_data_ = cached_session_info.initial_max_data;
    remembered_qtp.initial_max_streams_bidi_ = cached_session_info.initial_max_streams_bidi;
    // ... 拷贝所有记忆参数 ...
    remembered_tp.Init(remembered_qtp);
    send_flow_controller_.UpdateConfig(remembered_tp);
}
```

第三步是关键：**在握手完成之前，客户端就需要知道自己能发多少数据、能开多少条流**。如果不用记忆的传输参数预初始化流控制器，`MakeStream()` 在 0-RTT 阶段就无法工作——因为它不知道对端允许的窗口有多大。

### 0-RTT 密钥安装与 early data 信号

BoringSSL 在处理带 PSK 的 ClientHello 时，会通过 `SSL_QUIC_METHOD` 回调通知 QUIC 安装 0-RTT 写密钥。这条回调链最终落到 `ConnectionCrypto::SetWriteSecret()`（`src/quic/connection/connection_crypto.cpp`）：

```cpp
void ConnectionCrypto::SetWriteSecret(
    SSL* ssl, EncryptionLevel level, const SSL_CIPHER* cipher,
    const uint8_t* secret, size_t secret_len) {
    // ... 创建 cryptographer，安装密钥 ...

    // 当 0-RTT 写密钥就绪时，通知上层"可以开始发数据了"
    if (level == kEarlyData && early_data_ready_cb_) {
        early_data_ready_cb_();
    }
}
```

`early_data_ready_cb_` 是在 `ConnectionBase` 里注册的——它把 0-RTT 密钥就绪的事件"翻译"成"连接可用"的信号传给应用层：

```
BoringSSL: SSL_do_handshake()
  → SSL_QUIC_METHOD::set_write_secret(level = kEarlyData)
    → TLSConnection::SetWriteSecret()
      → ConnectionCrypto::SetWriteSecret(kEarlyData)
        → 安装 0-RTT 写密钥到 cryptographers_[kEarlyData]
        → early_data_ready_cb_()
          → handshake_done_cb_(shared_from_this())
            → 应用层收到"连接就绪"通知，可以开始发送数据
```

注意这里的设计选择：应用层看到的是统一的 `handshake_done_cb_`，不需要区分"0-RTT 就绪"还是"1-RTT 就绪"——对上层来说，连接可用就是可用。

### 发送调度：EncryptionLevelScheduler 的 0-RTT 优先级

有了密钥，还需要知道"什么时候该发 0-RTT 包"。`EncryptionLevelScheduler`（`src/quic/connection/encryption_level_scheduler.cpp`）管理着发送优先级：

```cpp
bool EncryptionLevelScheduler::TryGet0RttLevel(SendContext& ctx) {
    // 条件 1：当前还在 Initial 级别（握手未进阶到 Handshake）
    if (crypto_.GetCurEncryptionLevel() != kInitial) return false;
    // 条件 2：0-RTT 密钥已安装
    if (!crypto_.GetCryptographer(kEarlyData)) return false;
    // 条件 3：Initial 包已发出（ClientHello 必须先走）
    if (!initial_packet_sent_) return false;
    // 条件 4：有应用数据等待发送
    // → 全部满足，返回 kEarlyData 级别
    ctx.level = kEarlyData;
    return true;
}
```

四个条件缺一不可：当前级别必须是 Initial（说明握手还在进行中）、0-RTT 密钥已经安装、Initial Packet（携带 ClientHello）已经发出去了、并且应用层有数据等着发。这保证了 0-RTT 包永远出现在 ClientHello **之后**，符合 RFC 9001 的顺序要求。

在整体调度优先级中，0-RTT 排在第三位——低于跨级别 ACK 和路径探测，但高于普通的当前级别发送。

### 0-RTT 被拒时的回退

当服务端拒绝 0-RTT 时，BoringSSL 会在 `SSL_do_handshake()` 中返回 `SSL_ERROR_EARLY_DATA_REJECTED`。`TLSConnection::DoHandleShake()`（`src/quic/crypto/tls/tls_connection.cpp`）处理这个信号：

```cpp
if (ssl_err == SSL_ERROR_EARLY_DATA_REJECTED) {
    SSL_reset_early_data_reject(ssl_.get());  // 重置 early data 状态
    ret = SSL_do_handshake(ssl_.get());       // 重试完整 1-RTT 握手
}
```

`SSL_reset_early_data_reject` 清除 TLS 层的 early data 状态，然后重新调用 `SSL_do_handshake` 走完整的 1-RTT 流程。对上层应用来说，0-RTT 被拒后需要在 1-RTT 密钥就绪后重新发送之前的数据——**这些数据不会自动重传，因为 0-RTT 阶段的流状态已经被重置了**。

### 握手完成后的存储

当新连接的握手完成，客户端会把这次连接的 session 和传输参数存起来，为下一次 0-RTT 做准备（`ClientConnection::HandleHandshakeDoneFrame()`）：

```cpp
if (has_remote_tp_) {
    session_info.has_transport_params = true;
    session_info.initial_max_data = remote_initial_max_data_;
    session_info.initial_max_streams_bidi = remote_initial_max_streams_bidi_;
    // ... 保存所有传输参数 ...
}
SessionCache::Instance().StoreSession(session_der, session_info);
```

这形成了一个完整的闭环：**上一次连接的结尾存储 session → 下一次连接的开始恢复 session → 握手完成后再存储新的 session**。每一次成功的连接都在为下一次 0-RTT 积累"信任残影"。

---

## 9.6 快，不等于没有代价：0-RTT 应该怎样被理解

**0-RTT 不是一项性能优化，而是一次交易。**

交易的一端是时延收益：客户端可以把第一字节应用数据的发送时间提前整整一个 RTT，在高延迟网络下这是用户能直接感知到的体验改善。交易的另一端是安全边界：它只能用于"曾经见过面"的连接，它缺乏前向安全性，更重要的是——它无法防止重放攻击。

这意味着 **0-RTT 不是所有连接都该开启的默认魔法**。对于搜索、查询、读取这类幂等请求，0-RTT 是完美的加速器——重放一万次也不会造成实质伤害。但对于转账、支付、状态修改这类非幂等请求，0-RTT 就是危险的——没有人希望自己的转账请求被恶意重放。

QUIC 在这里做了一个诚实的设计选择：**不替应用层做决定**。协议层明确标注了 0-RTT 数据的安全属性——没有前向安全性、没有防重放保证——然后把"这条数据是否值得抢跑"的判断权交给了上层。这种"我不解决问题，但我把问题的边界讲清楚"的态度，贯穿了 QUIC 对待性能与安全之间张力的始终。

从 quicX 的实现来看，这场交易的工程代价同样不低。`SessionCache` 需要跨进程持久化 session 和记忆传输参数，`ConnectionCrypto` 需要在四个加密级别之间精确调度，`EncryptionLevelScheduler` 需要在严格的时序约束下决定何时可以发出 0-RTT 包。所有这些复杂度，都是为了让一个看似简单的承诺——"你点下按钮的瞬间，数据就已经在路上了"——真正兑现。
