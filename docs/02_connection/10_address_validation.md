# 10. 护城河：地址验证与防放大攻击

QUIC 在建连时延上已经做到了极致——1-RTT 握手压缩了往返次数，0-RTT 甚至让应用数据在握手完成前就上路了。但速度只是硬币的一面。当一个协议建立在 UDP 之上、又追求尽可能少的往返时，它天然缺少一个 TCP 世界里不用操心的东西：**对客户端来源地址的最低限度验证**。没有这层验证，服务器每回复一个包都可能是在喂养一次放大攻击。QUIC 必须在入口处同时架起护城河——让握手足够快，但绝不让速度变成武器。

---

## 10.1 没有三次握手之后：服务器为什么先吃亏

TCP 的世界里，客户端地址的真实性几乎是天然成立的。为什么？因为 TCP 有三次握手。

客户端发 SYN，服务器回 SYN-ACK，客户端再回 ACK——这三步来回看似只是在建连接，但服务器悄无声息地完成了一件事：**它确认了客户端确实能收到自己发往那个 IP 地址的包**。如果客户端伪造了源地址，它收不到 SYN-ACK，第三次握手永远不会发生，服务器也不会为这个伪造连接投入任何资源。

三次握手的隐藏价值就在这里：**它用最小的成本，帮服务器做了一个最基本的"存活证明"**。

但 QUIC 建立在 UDP 之上，而 UDP 没有三次握手。UDP 的信条是"发出去就不管了"——没有握手成本，也没有连接状态。这在高效率的场景下是优点，但在安全场景下就成了**致命的弱点**。

想象一个攻击者，它把 UDP 包的源地址伪造为受害者的 IP，然后发给 QUIC 服务器。服务器收到后回复 Initial 包甚至 Handshake 包——**这些回包会飞向伪造的源地址，也就是受害者的 IP**。攻击者发一个小包，就能让服务器回一个大得多的包去轰击受害者。这就是经典的 **UDP 放大攻击**（UDP amplification attack）。如果攻击者批量发送这种伪造包，服务器在不知情的情况下就成了攻击别人的武器。

这就是 QUIC 在设计之初就必须回答的问题：**在没有握手保障的 UDP 之上，服务器怎么才能确保自己不是在为一个根本不存在的客户端白干活？**

答案是**地址验证**（address validation）。在客户端被证明确实能收到服务器发往那个地址的包之前，服务器的发送行为必须受到严格限制。这就是 QUIC 护城河的第一道防线。

---

## 10.2 三倍红线：防放大攻击到底在限制什么

QUIC 为服务器设置了一条硬性规则，叫做 **anti-amplification**（防放大）限制。

具体来说：**在客户端的地址被验证之前，服务器发送给该客户端的数据量，不能超过服务器收到该客户端数据量的三倍**。

这里有一个容易被忽略的细节：RFC 9000 §8.1 说的是"所有归因于单个连接的**数据报负载字节数**"（datagram payload bytes），而且**被丢弃的数据报也计入已接收**——只要服务器认定该数据报属于这条连接，即使数据报因解密失败等原因被丢弃，它的字节数仍然增加发送预算。这一点对实现者来说很重要，因为它意味着接收计数发生在解密之前。

为什么是三倍？这个数字不是凭空拍脑袋定的。客户端的第一个 Initial 包至少 1200 字节（RFC 9000 §14.1 的最小 UDP 数据报大小要求）。按照三倍限制，服务器最多能回复 3600 字节——刚好足够发送 Initial ACK + Handshake 包，把握手推进到下一阶段，但又不会太多。

这条规则是**按字节量计算的，不是按包数**。如果按包数限制，服务器可以用一个超大的包绕过限制。QUIC 直接掐断了这个漏洞：不管你分几个包发，**总字节数不能超过收到的三倍**。

这对握手阶段的影响是巨大的。正常 TCP + TLS 握手，服务器可以毫无顾虑地往回发数据——ServerHello、证书、密钥交换参数、应用数据预告……只要 TCP 窗口允许，发多少都行。但 QUIC 不行。在客户端的地址被验证之前，服务器每发一个字节都要精打细算：还有多少"预算"可用？这个包发了之后，下一个包还有空间吗？

这种"发送预算"（send budget）的存在，让握手的设计发生了微妙的变化。服务器不能再像 TCP 那样"一口气把能发的都发了"，而必须把握手拆分成多个阶段：先发 Initial，收到客户端的进一步证明后再发 Handshake，最后才发 1-RTT。每个阶段的发送量都要严格控制在预算范围内。

对于实现者来说，这意味着必须在发送层做一个专门的 **anti-amplification 控制器**。每收到客户端一个包，这个控制器就要重新计算：服务器还能发多少？当前包会不会超预算？如果超了，就必须把数据拆到下一个包，或者干脆不发了。这个控制器必须和连接状态机紧密配合——只有当地址验证通过的那一刻，预算才会彻底放开。

这就是 QUIC 的设计张力所在：**它要追求低时延握手，但同时必须克制发送行为**。这两个目标之间存在天然的张力——服务器想在第一时间把握手往前推，但防放大限制逼着它一步一停，确认客户端确实在那个地址上。

---

## 10.3 Retry 不是拒绝服务，而是先问一句"你到底在不在这里"

有了防放大限制，服务器在地址验证之前不能随便发数据。但 QUIC 还需要一种更主动的机制来确认客户端的可达性。这就是 **Retry**（重试）机制的由来。

不过在讲 Retry 之前，必须先澄清一个容易产生的误解：**Retry 不是地址验证的唯一路径**。

RFC 9000 §8.1 定义了两种地址验证方式。第一种是**隐式验证**：当服务端成功处理了一个受 Handshake 密钥保护的数据包时，就意味着客户端确实在那个地址上——因为 Handshake 密钥来自本次连接的 (EC)DHE 交换，只有真正参与了握手的客户端才能生成正确的 Handshake 包。在正常的 1-RTT 握手中，当服务端收到客户端的 Handshake Finished 时，客户端的地址就被隐式验证了，三倍限制随即解除。

第二种是**显式验证**——Retry 就属于这一种。服务端在处理 Initial 包之前，先发一个 Retry 包要求客户端"回个话"，以此确认客户端的可达性。

那什么时候需要 Retry？**当三倍限制加上隐式验证不足以覆盖风险的时候**。比如服务器当前连接速率很高（可能正在遭受攻击）、或者某个 IP 的请求频率异常——这些场景下，服务器希望在投入任何握手资源之前，先用最低成本确认对方"确实在那里"。Retry 是高压场景下的额外防线，不是每条连接都必须走的路径。

Retry 的工作方式是这样的：当服务器收到客户端的第一个 Initial 包时，它不直接进入正常的握手流程，而是先回复一个特殊的 **Retry 包**。

这个 Retry 包里有两件关键的东西：

1. **一个 Token**：服务端用密钥和客户端地址信息生成的不透明令牌。
2. **一个新的 Connection ID**：让客户端用这个新 ID 继续后续的握手。

客户端收到 Retry 包后，必须把这个 Token 原封不动地装进下一个 Initial 包里，再发回给服务器。只有当服务器收到带 Token 的 Initial 包并验证通过，它才认为客户端"确实能收到自己发往那个地址的包"。

整个 Retry 交互的时序如下：

```
客户端                                              服务端
  │                                                  │
  │  ─── Initial Packet (DCID=X) ───────────────>    │
  │      [CRYPTO: ClientHello]                       │
  │      (无 Token)                                   │
  │                                                  │
  │                                                  │  决策：需要 Retry
  │                                                  │  生成 Token + 新 CID=Y
  │                                                  │
  │  <── Retry Packet ──────────────────────────     │
  │      [SCID=Y, Token=T, Retry Integrity Tag]     │
  │                                                  │
  │  验证 Retry Integrity Tag                        │
  │  保存 Token，更新 DCID → Y                        │
  │  重装 Initial Secret（用新 DCID=Y）               │
  │  重启 TLS 握手                                    │
  │                                                  │
  │  ─── Initial Packet (DCID=Y, Token=T) ──────>   │
  │      [CRYPTO: 新的 ClientHello]                  │
  │      (携带 Token)                                 │
  │                                                  │
  │                                                  │  验证 Token → 地址已确认
  │                                                  │  正常握手继续
  │                                                  │
  │  <── Initial ACK + Handshake Packet ──────────   │
  │      [ServerHello + Certificate + Finished]      │
  │                                                  │
        正常 1-RTT 握手继续（同第 8 章时序图）
```

你可能会问：这平白无故多了一个往返（客户端收到 Retry → 客户端再发一次 Initial），握手从 1-RTT 变成了 1.5-RTT，延迟反而增加了，划算吗？

答案是**划算**。因为这个额外的往返，换来的是服务器对客户端地址的确认。在没有 Retry 的情况下，服务器面对一个陌生 Initial 包，只能小心翼翼地发少量数据（防放大限制），生怕被人当枪使。但有了 Retry 之后，服务器可以更"大方"一点——因为它已经通过 Retry 确认了客户端的可达性，后面的握手就可以更顺畅地推进。

更重要的是，Retry 机制把"确认客户端地址"这个成本，从服务器一个人扛，变成了服务器和客户端共同分担。服务器只需要多发一个短小的 Retry 包（通常只有几十字节），就能换取对客户端真实性的高度信心。

所以 Retry 不是"握手失败了"，而是**握手路径上的一次"安检"**。它不是拒绝服务，而是先问一句"你到底在不在这里"，确认过眼神（地址）之后，才放行进入下一阶段。

---

## 10.4 一张有期限的门票：Token 在地址验证里扮演什么角色

Retry 机制的核心不是那个额外的包，而是包里的 **Token**。理解 Token 的设计，是理解整个地址验证逻辑的关键。

Token 是什么？从协议的角度，它就是一个不透明的字节串——客户端不需要知道它的内部结构，只需要把它带回来。但从设计的角度，Token 是地址验证的"门票"。

这张门票有几个关键特性：

**第一，它有过期时间**。Token 不是永久有效的。服务端在生成 Token 时会嵌入时间戳，验证时检查它是否已过期。在 quicX 的实现中，Retry Token 的默认有效期是 60 秒。过期机制配合 Token 本身只在连接建立阶段使用这一事实，天然地限制了它的重放窗口——攻击者即使截获了 Token，也只有极短的时间可以利用。

**第二，服务端可以做成无状态的**。这里有点微妙：如果服务端为每个 Token 都存一份"已使用"的记录，就需要庞大的状态存储。更好的设计是**把状态加密进 Token 本身**。服务端用自己的密钥，把客户端的地址信息、原始连接 ID、时间戳等"打包"签名后发给客户端。客户端下次带 Token 回来时，服务端验证签名，就能知道"这个 Token 是不是我发的、什么时候发的、客户端地址对不对"。Token 本身就是状态携带者。

**第三，它绑定了地址**。Token 的 HMAC 签名把客户端的 IP 地址纳入了计算输入。服务器验证 Token 时会重建这个签名——如果客户端中途换了 IP（比如从 WiFi 切到 4G），HMAC 就对不上，Token 失效。这也是 QUIC 防御地址伪造的另一种手段。

**第四，它和 Initial Secret 重装有关**。这是一个容易被忽视的细节：当客户端收到 Retry 包后，它不能继续用原来的 Initial Secret 加密下一个 Initial 包。因为服务端已经换了一个新的 Connection ID，双方需要重新派生 Initial Secret（用新的 DCID 和 Initial Salt）。这个过程叫做 **Initial Secret 重装**（Initial Secret reinstall）。quicX 的实现必须处理这个重装逻辑——收到 Retry 后，清除旧的 Initial Secret，用新的 DCID 派生一个全新的。

**第五，Token 不只有 Retry 一种来源**。RFC 9000 定义了两种地址验证 Token：

- **Retry Token**：在 Retry 包中发送，用于当前连接尝试的地址验证。这是本章重点讨论的场景。
- **NEW_TOKEN 帧 Token**：在已建立的连接中通过 `NEW_TOKEN` 帧发送给客户端，客户端保存后可以在**未来的新连接**中携带。服务端收到带有 NEW_TOKEN Token 的 Initial 包时，可以跳过 Retry 直接接受连接——因为客户端的地址已经在上一次连接中被验证过了。

NEW_TOKEN 的意义在于：**它让"老客户"不用每次都过安检**。第一次连接时可能走 Retry，但连接建立后服务端发一个 NEW_TOKEN 帧，客户端下次来时带着这个 Token，就能直接免检通过。这和 0-RTT 的 Session Ticket 形成了有趣的对称——一个让加密不用重新协商，一个让地址不用重新验证。

Token 就是这样扮演着"地址验证与状态传递"的双重角色。它让服务器在不保存状态的情况下，依然能确认客户端的真实性。

---

## 10.5 quicX 的防线：Retry、Token 与放大量控制怎样落到实现里

理解了协议层面的地址验证机制，我们现在来看看 quicX 是怎么在代码里落实这套防线的。quicX 的实现涉及四个核心模块的协作：**ServerWorker**（Retry 决策）、**RetryTokenManager**（Token 生成与验证）、**AntiAmplificationController**（发送预算）和 **ClientConnection**（客户端 Retry 处理）。

### 第一道关卡：ServerWorker 的 Retry 决策

Retry 是一个昂贵的操作——它增加了一个往返。所以 quicX 不是对所有连接都发 Retry，而是提供了三种策略（`src/quic/include/if_quic_server.h`）：

```cpp
enum class RetryPolicy {
    NEVER,      // 从不发送 Retry（性能优先）
    SELECTIVE,  // 动态决策：基于服务器负载和 IP 行为
    ALWAYS      // 总是发送 Retry（安全优先）
};
```

`SELECTIVE` 模式是最有意思的一种——它只在服务器"觉得不太对劲"的时候才触发 Retry。`ShouldSendRetry()` 的决策逻辑（`src/quic/quicx/worker_server.cpp`）：

```cpp
bool ServerWorker::ShouldSendRetry(bool has_valid_token, const common::Address& client_addr) {
    if (has_valid_token) return false;  // 已有合法 Token，不再 Retry

    switch (retry_policy_) {
        case RetryPolicy::NEVER:  return false;
        case RetryPolicy::ALWAYS: return true;
        case RetryPolicy::SELECTIVE: {
            // 检查 1：全局连接速率过高（可能正在遭受攻击）
            if (rate_monitor_ && rate_monitor_->IsHighRate(selective_config_.rate_threshold_))
                return true;
            // 检查 2：该 IP 行为可疑（短时间内大量连接）
            if (ip_limiter_ && ip_limiter_->IsSuspicious(client_addr))
                return true;
            // 正常情况：直接接受连接
            return false;
        }
    }
}
```

注意 Retry 决策发生在连接创建**之前**——它是 `ServerWorker`（Worker 层）的职责，不是 `ServerConnection`（连接层）的职责。这是一个重要的分层选择：Worker 手里有全局视角（连接速率、IP 行为），而单个连接没有这些信息。

整条 `InnerHandlePacket()` 的处理路径是：查找已有连接 → Initial 包合法性检查 → 记录连接速率和 IP 行为 → 如果包含 Token 则验证 → 调用 `ShouldSendRetry()` 决策 → 发 Retry 或创建新连接。

### Token 的编码格式与验证：RetryTokenManager

`RetryTokenManager`（`src/quic/connection/retry_token_manager.h`）负责 Token 的生成和验证。Token 的编码格式：

```
Token = timestamp(8B) || cid_len(1B) || original_dcid(N B) || HMAC-SHA256(32B)
```

HMAC 的输入不只是 Token 里的字段——它还包含了 **Token 本身不包含的客户端 IP 地址**：

```
HMAC_payload = client_ip || timestamp || cid_len || original_dcid
```

这个设计很巧妙：Token 本身不暴露客户端 IP（减少信息泄露），但验证时通过从网络层获取的客户端地址重建 HMAC 输入，从而把地址绑定进了签名。如果客户端换了 IP，HMAC 就对不上。

生成过程（`GenerateToken()`）：

```cpp
std::string RetryTokenManager::GenerateToken(
    const common::Address& client_addr, const ConnectionID& original_dcid) {
    // 自动检查密钥是否需要轮换（每 24 小时）
    uint64_t now = std::time(nullptr);
    if (now - last_rotation_time_ > ROTATION_INTERVAL) {
        RotateSecret();
    }

    // 构建 HMAC 输入：client_ip || timestamp || cid_len || cid
    std::string payload;
    payload += client_addr.GetIp();
    payload.append((char*)&timestamp, sizeof(timestamp));
    uint8_t cid_len = original_dcid.GetLength();
    payload.append((char*)&cid_len, sizeof(cid_len));
    payload.append((char*)original_dcid.GetID(), cid_len);

    // HMAC-SHA256 签名
    std::string hmac;
    RetryCrypto::ComputeTokenHMAC(payload, current_secret_, hmac);

    // 最终 Token = timestamp || cid_len || cid || HMAC
    std::string token;
    token.append((char*)&timestamp, sizeof(timestamp));
    token.append((char*)&cid_len, sizeof(cid_len));
    token.append((char*)original_dcid.GetID(), cid_len);
    token.append(hmac);
    return token;
}
```

验证过程（`ValidateToken()`）做四件事：检查 Token 最小长度（≥41 字节）、检查时间戳是否过期（默认 60 秒）、重建 HMAC 输入并用当前密钥验证签名、如果失败再用上一轮密钥重试（密钥轮换窗口）。所有 HMAC 比较都使用**常量时间比较**以防止 timing attack。

密钥轮换逻辑也值得一提：每 24 小时自动轮换一次，旧密钥保留一个轮换周期。这意味着在轮换发生的前后，用旧密钥签发的 Token 仍然可以被验证——不会因为密钥刚好轮换而导致合法客户端被拒。

### 三倍红线的守门人：AntiAmplificationController

`AntiAmplificationController`（`src/quic/connection/controler/anti_amplification_controller.h`）把 RFC 9000 §8.1 的三倍限制翻译成了精确的字节级控制：

```cpp
class AntiAmplificationController {
private:
    bool is_unvalidated_;
    uint64_t sent_bytes_;
    uint64_t received_bytes_;

    static constexpr uint64_t kAmplificationFactor = 3;
    static constexpr uint64_t kDefaultInitialCredit = 400;
    static constexpr double kNearLimitThreshold = 0.9;
};
```

`kAmplificationFactor = 3` 就是 RFC 9000 的三倍限制。`kDefaultInitialCredit = 400` 是初始信用——在收到任何客户端数据之前，服务端就允许发送 `400 × 3 = 1200` 字节，刚好够发一个 PATH_CHALLENGE。

核心的 `CanSend()` 方法在每次发包前被调用：

```cpp
bool AntiAmplificationController::CanSend(uint64_t bytes) const {
    if (!is_unvalidated_) return true;  // 地址已验证，无限制
    uint64_t max_allowed = received_bytes_ * kAmplificationFactor;
    return (sent_bytes_ + bytes) <= max_allowed;
}
```

当地址验证通过（隐式验证或 Retry Token 验证成功），`ExitUnvalidatedState()` 被调用——`is_unvalidated_` 变为 `false`，此后所有 `CanSend()` 直接返回 `true`，发送预算彻底放开。

### 客户端的 Retry 处理链路

当客户端收到 Retry 包时，`ClientConnection::OnRetryPacket()`（`src/quic/connection/connection_client.cpp`）需要完成五个步骤的重置与重建：

```cpp
bool ClientConnection::OnRetryPacket(std::shared_ptr<IPacket> packet) {
    // Step 1: 提取新的 Server CID，保存 Token
    ConnectionID src_cid(long_header->GetSourceConnectionId(), ...);
    cid_coordinator_->GetRemoteConnectionIDManager()->AddID(...);
    cid_coordinator_->GetRemoteConnectionIDManager()->UseNextID();
    token_ = std::string((char*)token_span.GetStart(), token_span.GetLength());
    send_manager_.SetToken(token_);  // 后续 Initial 包会自动携带

    // Step 2: 重置 TLS（重建 SSL 对象，重新设置 ALPN 和传输参数）
    tls_conn->Reset(saved_alpn_);
    // 设置 original_destination_connection_id 传输参数
    updated_tp.original_destination_connection_id_ =
        std::string((char*)original_dcid_.GetID(), original_dcid_.GetLength());
    transport_param_.Init(updated_tp);

    // Step 3: 重置 QUIC 加密状态
    send_manager_.ResetInitialPacketNumber();  // 包号归零
    crypto_stream->ResetForRetry();            // 偏移量归零
    connection_crypto_.Reset();                // 清除旧密钥

    // Step 4: 用 Retry 包的 SCID 重装 Initial Secret
    connection_crypto_.InstallInitSecret(src_cid.GetID(), src_cid.GetLength(), false);
    tls_conn->DoHandleShake();  // 重启 TLS，生成新 ClientHello

    // Step 5: 触发 Initial 包重发
    retry_received_ = true;     // 防止重复处理
    ActiveSendStream(crypto_stream);
    return true;
}
```

这五步缺一不可。Step 2 中设置 `original_destination_connection_id` 尤其关键——RFC 9000 §17.2.5.3 要求客户端在响应 Retry 时必须包含最初使用的 DCID，这让服务端能把带 Token 的新 Initial 和之前收到的旧 Initial 关联起来。

这四个模块的协作，构成了 quicX 的完整防线。它横跨 Worker 层（全局决策）、连接层（状态机）、密码层（Token 签名与 Initial Secret 重装）和发送层（预算控制），不是某个模块的独立功能，而是多个模块共同编织的一张安全网。

---

## 10.6 快与稳之间：这一章真正要讲的不是保守，而是节制

QUIC 在入口处有两张面孔。

一张朝向客户端：1-RTT 握手压缩往返，0-RTT 让数据在握手完成前就上路，能抢一毫秒是一毫秒。另一张朝向攻击者：三倍限制卡住发送预算，Retry 要求先证明自己在那个地址上，Token 把无状态的验证编码成一张有期限的门票。

这两张面孔并不矛盾。**0-RTT 解决的是"客户端想更快"的问题，地址验证解决的是"服务器不能被滥用"的问题**。它们共同构成了 QUIC 建连的完整图景：一边是冲锋的速度，一边是防守的堤坝。

Retry 与 Token，本质上都是"节制"思维的体现——它们让 QUIC 能在追求极致性能的同时，保持对安全边界的高度警觉。quicX 的实现把这种节制落到了四个模块的协作中：Worker 层拿着全局视角做 Retry 决策，RetryTokenManager 用 HMAC 签名把地址绑进 Token，AntiAmplificationController 用两个计数器守住三倍红线，ClientConnection 在收到 Retry 后五步重建握手状态。这些模块各自只做一件事，但合在一起就编织出了一张横跨决策层、密码层、连接层和发送层的安全网。

**QUIC 在入口处既激进又保守**。激进的地方在于它要把握手延迟压到极限；保守的地方在于它绝不允许速度变成攻击的杠杆。这不是妥协，而是一个协议成熟的标志——真正的速度，从来不是不计代价的冲刺。
