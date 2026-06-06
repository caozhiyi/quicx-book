<div align="center">

# 深入解析 QUIC 与 HTTP/3

### 从协议设计到 quicX 网络库工程实践

<p>
  <a href="https://caozhiyi.github.io/quicx-book/"><img src="https://img.shields.io/badge/📖_在线阅读-mkdocs-2196F3?style=for-the-badge" alt="在线阅读"></a>
  <a href="https://github.com/caozhiyi/quicX"><img src="https://img.shields.io/badge/🔧_quicX_源码-GitHub-181717?style=for-the-badge" alt="quicX"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-CC_BY--NC--SA_4.0-lightgrey?style=for-the-badge" alt="License"></a>
</p>

</div>

---

这本书脱胎于 [quicX](https://github.com/caozhiyi/quicX) —— 一个从零手写、完全基于 C++ 打造的生产级 QUIC / HTTP/3 网络库。

不单调地翻译 RFC，不照本宣科地罗列网络状态机，而是**回到那个充满未知与代码 Bug 的工程现场**——如何用 One-Loop-Per-Thread 破开 UDP 高并发的迷雾？如何将 TLS 1.3 强行揉入传输层实现毫秒级加密握手？如何与悬垂指针和内存泄漏搏斗？

> *"纸上得来终觉浅，绝知此事要躬行。很多设计规则只通过看书看文章很难理解透彻，只有知道了为什么不好，才能知道这些模式为什么好。"*

---

## 📖 在线阅读

**🌐 推荐方式：[在线版（mkdocs）](https://caozhiyi.github.io/quicx-book/)** — 提供完整的目录导航、暗黑模式、代码高亮和系统结构配图。

也可以直接点击下方目录跳转到 GitHub 上的对应章节。

---

## 📚 全书结构

全书 **7 卷 35 章**，从底层的高性能 C++ 基础设施开始，一步步构建出完整的 QUIC 和 HTTP/3 协议栈。每一卷都是下一卷的地基。

<details>
<summary><b>📘 卷一：基石时代</b> · 内存池 · 零拷贝 · 事件循环 · 无锁并发 · 异步定时器</summary>

| 章 | 标题 |
|---|---|
| 0 | [卷一导读：在用户态重建网络世界的代价](docs/01_infrastructure/00_intro.md) |
| 1 | [内存的七巧板: 连接级内存池的设计](docs/01_infrastructure/01_memory_pool.md) |
| 2 | [拷贝的艺术: 零拷贝 Buffer 的生存哲学](docs/01_infrastructure/02_zero_copy_buffer.md) |
| 3 | [管道与枢纽: 网络 IO 的架构抽象](docs/01_infrastructure/03_network_io_abstraction.md) |
| 4 | [打破全局锁: One-Loop-Per-Thread 的无锁演进](docs/01_infrastructure/04_thread_model_and_lockfree.md) |
| 5 | [时空的刻度: 高效定时器与事件循环的融合](docs/01_infrastructure/05_async_timer.md) |

</details>

<details>
<summary><b>📗 卷二：破冰之旅</b> · Packet 解剖 · Initial 密钥 · TLS 握手 · 0-RTT · 连接迁移</summary>

| 章 | 标题 |
|---|---|
| 0 | [卷二导读：打破四元组枷锁，重建连接的定义](docs/02_connection/00_intro.md) |
| 6 | [万物开端: QUIC Packet 解剖与连接世界地图](docs/02_connection/06_packet_and_frame_anatomy.md) |
| 7 | [公开的秘密: Initial 密钥与 CRYPTO Frame 的起步逻辑](docs/02_connection/07_initial_keys_and_crypto_frame.md) |
| 8 | [破冰之握: 连接建立与 TLS 融合](docs/02_connection/08_handshake_and_tls.md) |
| 9 | [零等待的奇迹: 0-RTT 与会话恢复](docs/02_connection/09_zero_rtt_and_session_resume.md) |
| 10 | [护城河: 地址验证与防放大攻击](docs/02_connection/10_address_validation.md) |
| 11 | [连接的生死簿: 状态机与传输参数协商](docs/02_connection/11_connection_state_and_params.md) |
| 12 | [会飞的连接: Connection ID 与路径迁移](docs/02_connection/12_connection_id_and_migration.md) |

</details>

<details>
<summary><b>📙 卷三：字节的契约</b> · 序列号空间 · ACK · 丢包探测 · 语义重传 · 发包管线</summary>

| 章 | 标题 |
|---|---|
| 0 | [重构可靠传输：从包级确认到语义重传](docs/03_reliable/00_intro.md) |
| 13 | [可靠性的代价: QUIC 为什么不再照搬 TCP](docs/03_reliable/13_why_quic_rebuilds_reliability.md) |
| 14 | [ACK 的艺术: 序列号空间与确认边界](docs/03_reliable/14_pn_space_and_ack.md) |
| 15 | [消失与追踪: 丢包探测与 PTO 幽灵](docs/03_reliable/15_loss_detection_and_pto.md) |
| 16 | [重传的边界: 重发的不是 Packet, 而是语义](docs/03_reliable/16_retransmission_semantics.md) |
| 17 | [发包管线: PacketBuilder 与加密层调度](docs/03_reliable/17_packet_builder_and_encryption.md) |
| 18 | [刺刀见红: 异步定时器与连接生命周期的暗战](docs/03_reliable/18_timer_and_lifecycle_war_story.md) ⭐ |

</details>

<details>
<summary><b>📕 卷四：速度与节奏</b> · RTT 测量 · Reno/AIMD · Cubic · BBR 演进 · 工程实践</summary>

| 章 | 标题 |
|---|---|
| 0 | [拥塞控制：网络管道的物理学与控制论](docs/04_congestion/00_intro.md) |
| 19 | [管道的容量: RTT 测量与拥塞窗口的第一原理](docs/04_congestion/19_rtt_and_cwnd.md) |
| 20 | [丢包即信号: Reno 与 AIMD 的经典控制](docs/04_congestion/20_reno_and_aimd.md) |
| 21 | [立方的野心: Cubic 与高 BDP 网络的攻防](docs/04_congestion/21_cubic_and_high_bdp.md) |
| 22 | [模型的革命: BBR 三代演进与算法共存](docs/04_congestion/22_bbr_evolution_and_coexistence.md) |
| 23 | [速度的手术台: quicX 中拥塞控制的工程实践](docs/04_congestion/23_bbr_in_quicx.md) ⭐ |

</details>

<details>
<summary><b>📔 卷五：河流与闸门</b> · 队头阻塞 · Stream 状态机 · 双层流控 · 背压机制</summary>

| 章 | 标题 |
|---|---|
| 0 | [多路复用与流控：并发的秩序与背压机制](docs/05_flow_and_stream/00_intro.md) |
| 24 | [从队头阻塞到传输层并发: Stream 为什么是 QUIC 的另一半身体](docs/05_flow_and_stream/24_multiplexing_history.md) |
| 25 | [流的诞生与终结: 发送与接收状态机](docs/05_flow_and_stream/25_stream_state_machine.md) |
| 26 | [双层流控与背压: 额度如何限制流，闸门关上后又如何打开](docs/05_flow_and_stream/26_flow_control_windows.md) |
| 27 | [quicX 的 Stream 管理: 从 pending 到 manager 的工程全景](docs/05_flow_and_stream/27_blocked_and_max_frames.md) |

</details>

<details>
<summary><b>📓 卷六：抵达彼岸</b> · HTTP/3 帧体系 · 请求映射 · QPACK 头压缩 · 连接生命周期</summary>

| 章 | 标题 |
|---|---|
| 0 | [抵达彼岸: HTTP/3 与乱序世界的契约](docs/06_http3/00_intro.md) |
| 28 | [换一张地图: HTTP/3 的帧体系与控制面](docs/06_http3/28_http3_frame_anatomy.md) |
| 29 | [重新映射: 从 QUIC 流到请求与响应](docs/06_http3/29_http3_mapping.md) |
| 30 | [QPACK: 乱序世界里的头压缩引擎](docs/06_http3/30_qpack_compression.md) |
| 31 | [一条 HTTP/3 连接的一生](docs/06_http3/31_http3_connection_lifecycle.md) |

</details>

<details>
<summary><b>📒 卷七：生产级修养</b> · Metrics · Qlog · 协议协商 · Nginx/Quiche 互联互通</summary>

| 章 | 标题 |
|---|---|
| 0 | [生产级修养：从可用网络协议到工业级基础设施](docs/07_engineering/00_intro.md) |
| 32 | [透明的眼睛: Metrics、日志上下文与可观测性基座](docs/07_engineering/32_metrics.md) |
| 33 | [黑匣子: Qlog 可观测性实践](docs/07_engineering/33_qlog.md) |
| 34 | [通天塔的阶梯: HTTP 协议协商与版本升级](docs/07_engineering/34_protocol_upgrade.md) |
| 35 | [试炼场: 与 Nginx / Quiche 的互联互通](docs/07_engineering/35_interop_test.md) |

</details>

---

## 🧭 阅读建议

**从头读到尾**：推荐。每一章的结尾自然引出下一章的问题，也是 `quicX` 真实的开发演进路线。

**带着问题来**：
- 想搞清楚 **QUIC 为什么不照搬 TCP** → 卷三，第 13 章
- 想理解 **BBR 在实际代码中怎么落地** → 卷四，第 23 章
- 想看懂 **连接迁移与 Connection ID 的设计** → 卷二，第 12 章
- 想了解 **HTTP/3 如何解决队头阻塞** → 卷六，第 24 + 28 章

---

## 🛠️ 本地构建

```bash
pip install -r requirements.txt
mkdocs serve        # http://127.0.0.1:8000
```

---

## 🌟 关于作者

我是 **caozhiyi**，做了多年网络和分布式系统架构。这本书和 `quicX` 来自我在QUIC实现中探索高吞吐、低延迟传输协议时踩过的坑，以及在攻克各种 C++ 异步并发 Bug 时沉淀的思考。

> 📮 公众号：**煮码宝藏** — 持续分享 QUIC / HTTP3、C++ 异步系统设计、网络协议底层技术。

---

## 🤝 参与与反馈

- 🐛 文字纰漏或技术错误 → [提 Issue](https://github.com/caozhiyi/quicx-book/issues)
- 💡 对实现细节有更好的想法 → [提 PR](https://github.com/caozhiyi/quicx-book/pulls)
- ❓ 对推导或代码有疑问 → [Discussions](https://github.com/caozhiyi/quicx-book/discussions)
- ⭐ 觉得有用？**Star 是对作者最大的鼓励**

---

## 📜 协议

本书采用 [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/deed.zh) 协议。可以自由阅读、传播和二次创作（需署名 + 同协议），禁止商业用途。

---

<div align="center">

**希望你在这本书中，找到破译下一代互联网基础设施的乐趣。**

</div>
