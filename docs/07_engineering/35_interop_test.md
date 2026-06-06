# 35. 试炼场：与 Nginx / Quiche 的互联互通

一个协议库可以跑通所有单元测试，每一帧的编码解码都严格对齐 RFC，每一条状态机的转换都有断言守护——但这只能证明它和自己的理解一致，不能证明它和世界的理解一致。协议实现的最终考试不在实验室里，而在两个完全独立的代码库第一次握手的那一瞬间。

---

## 35.1 自测的盲区：为什么必须和别人对话

自己的 client 和自己的 server 共享同一份源码、同一个作者、同一套对 RFC 的理解。如果双方都把某条规则理解错了——比如都认为 Retry 后包号应该重置为零、都认为 Initial 包可以用单字节编码包号、都认为 ACK 延迟可以无限推迟——单元测试全过，集成测试也全过。

**只有当两个独立实现基于同一份 RFC 各自编码、然后握手时，那些"RFC 没说清楚"的灰色地带才会暴露出来。**

RFC 给了实现者大量自由度：PADDING 帧的放置位置没有硬性规定、ACK 的发送频率只有 SHOULD 级别的建议、Initial 包的 SCID 长度只设了上限不设下限、拥塞窗口的初始值可以在一定范围内选择。每个实现在这些自由度上做了不同的选择，而这些选择在自测时完全不可见——你的 client 永远不会对你的 server 发一个 SCID 长度为零的 Initial 包，因为你的 client 和 server 用的是同一个生成逻辑。

互联互通测试的本质是用**多样性暴露假设**。十二个 QUIC 实现代表十二种对 RFC 的独立阅读，十二种编程语言和风格，十二种对"合理默认值"的不同判断。当 quicX 和 quiche 握手时，quiche 的 Rust 严格性会毫不客气地拒绝 quicX 发出的任何不合规字节；当 quicX 和 ngtcp2 传输文件时，ngtcp2 的流控策略可能和 quicX 完全不同，逼迫双方在背压协商上达成真正的一致。

这种考验是单元测试永远给不了的——因为单元测试的对端永远是你自己。

还有一类更隐蔽的问题：**性能假设的差异**。你的拥塞控制可能假设对端会在收到数据后 25ms 内发送 ACK，但如果对端的 ACK 延迟策略是 100ms 呢？你的 PTO 计算可能因此频繁触发虚假超时，导致不必要的重传风暴。这不是 bug，两边都符合 RFC，但组合在一起就是灾难。

---

## 35.2 QUIC Interop Runner：社区的试金石

IETF QUIC 工作组维护了一个官方互操作测试框架——quic-interop-runner。它为所有 QUIC 实现定义了统一的接入规范：

- 一个 `manifest.json` 声明实现支持的能力和测试场景；
- 一个 `run_endpoint.sh` 作为 Docker 容器的入口脚本统一启停接口；
- 一个 `Dockerfile` 将实现打包为标准化的测试镜像。

三个文件，就是一个实现加入社区互操作矩阵的全部门票。

quicX 的 manifest 声明了完整的 14 个标准场景支持：handshake、transfer、retry、resumption、zerortt、http3、multiconnect、versionnegotiation、chacha20、keyupdate、v2、rebind-port、rebind-addr、connectionmigration。同时声明支持 qlog 输出、ECN 标记、ChaCha20 密码套件、会话恢复、0-RTT、QUIC v2——这意味着 quicX 可以参加社区矩阵测试的每一个项目。

`run_endpoint.sh` 是整个接入规范的核心枢纽。框架通过 `ROLE` 环境变量区分角色——`server` 走 `run_server()` 分支，`client` 走 `run_client()` 分支，其他值直接 `exit 1`。这个脚本做的事情看似简单，实则精妙：它根据 `TESTCASE` 环境变量动态拼接命令行参数。

retry 场景给服务端加 `--force-retry`；versionnegotiation 给客户端加 `--force-version 0x1a2a3a4a`；chacha20 给双端加 `--cipher TLS_CHACHA20_POLY1305_SHA256`；resumption 和 zerortt 给客户端加 `--session-cache /tmp/session`；v2 给双端加 `--quic-version 2`。框架还传入 `QLOGDIR` 和 `SSLKEYLOGFILE` 两个路径——前者让实现输出 qlog 供事后分析，后者让 Wireshark 能解密抓包。

对于不支持的测试用例，脚本返回退出码 **127**——这是 quic-interop-runner 框架的约定，表示"未实现"而非"失败"。矩阵结果表中"不支持"和"失败"是完全不同的语义：前者是你没做，后者是你做错了。

测试协议使用的是 hq-interop（HTTP/0.9 over QUIC），请求格式是简单的 `GET /path\r\n`。选择这个极简协议而非完整的 HTTP/3 是刻意的——互操作测试的目标是验证传输层行为，不是验证应用层语义。用最简单的请求格式，可以把变量控制到最少，让每个测试场景都精确地考验它要考验的那一个协议机制。

`testcases.py` 是场景定义的核心。它用 `TEST_FILE_SIZES` 字典定义了 11 种文件尺寸梯度：

```
32B / 1KB / 5KB / 10KB / 100KB / 500KB / 1MB / 2MB / 3MB / 5MB / 10MB
```

每个 `TestScenario` 是一个 dataclass，包含名称、描述、使用的文件列表、双端环境变量、是否需要两次连接、并发客户端数量。不同场景使用不同的文件尺寸——handshake 只传 1KB（够验证连接就行），transfer 传 1MB 和 5MB（考验流控和拥塞控制），keyupdate 传 2MB（让密钥更新发生在传输中间而不是快结束时），connectionmigration 和 rebind 系列传 5MB（保证迁移发生在活跃传输阶段）。这些尺寸不是随意选的——太小无法触发待测机制，太大则测试耗时过长。

---

## 35.3 Docker 三容器拓扑与跨实现矩阵

互操作测试不能在理想网络上跑——真实世界有延迟、有带宽限制、有丢包。quic-interop-runner 的 `docker-compose.yml` 定义了一个三容器拓扑：

- **sim**（ns-3 网络模拟器）——位于 server 和 client 之间，所有流量必须经过它
- **server**（QUIC 服务端）——挂在 rightnet 网络，IP 固定 193.167.100.100
- **client**（QUIC 客户端）——挂在 leftnet 网络，IP 固定 193.167.0.100

sim 容器注入的默认网络条件是 `simple-p2p --delay=15ms --bandwidth=10Mbps --queue=25`：15ms 单向延迟（30ms RTT）、10Mbps 带宽、25 个包的队列深度。对于 rebind 测试，sim 还会按配置周期性地改变 NAT 映射，模拟移动网络下的地址漂移。

两个 Docker 网络——leftnet（子网 193.167.0.0/24）和 rightnet（子网 193.167.100.0/24）——都禁用了 IP masquerade，确保流量不会走 Docker 默认的 NAT 捷径。sim 容器两个网卡分别拿 193.167.0.2 和 193.167.100.2，作为两个网络之间唯一的桥接点。这种拓扑保证了每一对 client-server 组合在完全相同的网络条件下被测试，结果具有可比性。

容器的 capability 配置值得一提。sim 需要 `NET_ADMIN` 和 `NET_RAW` 两个 capability——前者操控路由表和流量控制队列，后者注入丢包和延迟。server 和 client 只需 `NET_ADMIN`。

一个容易被忽略的配置是 `ulimits.memlock: 67108864`（64MB）——QUIC 的加密操作需要锁定内存页防止密钥被交换到磁盘，Docker 默认的 memlock 限制太小。不加这个配置，BoringSSL 在分配加密上下文时直接失败，表现出来就是握手超时——这种问题调试起来极其痛苦，因为错误信息完全不指向内存锁定。

卷挂载的设计也体现了测试的严谨性。服务端把 `www` 目录以只读方式挂入（`:ro`），确保测试文件不会被意外修改；证书目录同样只读。客户端的 `downloads` 目录用 `:delegated` 模式挂载——这是 macOS Docker 的性能优化，允许容器先写入再同步到宿主机，避免大文件下载时的 I/O 瓶颈。日志目录和 qlog 目录分别挂载到宿主机的 `logs/server` 和 `logs/client`，测试失败后可以直接在宿主机上分析 qlog 和 TLS key log。

Dockerfile 使用两阶段构建。第一阶段基于 `ubuntu:22.04`，安装全量编译工具链，CMake 配置只开启 `ENABLE_INTEROP=ON`，其余组件全部显式关闭：

```
-DENABLE_TESTING=OFF -DENABLE_BENCHMARKS=OFF
-DENABLE_FUZZING=OFF -DENABLE_CC_SIMULATOR=OFF
-DENABLE_INTERGRATION=OFF -DENABLE_INTEROP=ON
```

> 注意：`INTERGRATION` 是源码中的历史拼写（正确拼法应为 `INTEGRATION`），此处保留与源码一致。

干净地只构建 `interop_server` 和 `interop_client` 两个二进制。第二阶段基于 `martenseemann/quic-network-simulator-endpoint:latest`——这个基础镜像由 quic-interop-runner 项目维护，内置了 `/setup.sh`（配置网络命名空间和路由表）和 `/wait-for-it.sh`（等待 sim 容器就绪后才启动端点）。最终镜像只装 `libssl3` 和 `ca-certificates` 两个运行时依赖，暴露 443/udp 端口。编译器、头文件、源码全都留在构建阶段，不会出现在最终镜像里。

quicX 的 `interop_runner.py` 是一个 1600 行的 Python 编排引擎，支持三种运行模式：

- `--local` 模式直接用本地编译的二进制，跳过 Docker，改一行代码重新编译后几秒钟就能重跑场景。这个模式在调试互操作 bug 时价值巨大——你可以在本地 gdb 调试服务端的同时让远端客户端发起连接，断点打在哪一行都行。
- 默认的 Docker 模式构建 quicX 镜像后与指定的对端实现配对测试。
- `--matrix` 模式全矩阵交叉——`--implementations quicx,quiche,ngtcp2` 产生 9 对组合（3×3），每对跑全部 14 个场景，总共 126 个测试点。

quicX 的 `implementations.json` 注册了 12 个 QUIC 实现的 Docker 镜像：quiche、ngtcp2、quic-go、mvfst、quinn、aioquic、picoquic、neqo、lsquic、msquic、s2n-quic——覆盖了 C/C++、Rust、Go、Python、Haskell 等多种语言生态。

测试结果的验证标准很简单也很严格：**字节级文件比对**。客户端下载的文件和服务端提供的原始文件逐字节比较，任何差异都意味着测试失败——不是"内容大致正确"，不是"长度一样"，而是每一个字节都必须完全相同。结果以 markdown 矩阵表格输出，每个单元格是通过/失败/不支持三种状态之一。在 CI 中，任何一个"失败"单元格都会阻止代码合入。

---

## 35.4 十四种场景背后的协议深水区

14 个标准场景不是随意挑选的，每一个都对准了协议实现中最容易出分歧的区域。

**handshake** 和 **transfer** 是基线。handshake 只传 1KB 的小文件，验证 Initial 交换、密钥安装、连接建立和正常关闭这条最核心的路径能不能走通。transfer 传 1MB 和 5MB 两个文件，考验流控推进、拥塞控制响应、多流复用。如果这两个过不了，后面都不用测了。

**retry** 考验地址验证。服务端通过 `FORCE_RETRY=1` 环境变量强制对每个连接发送 Retry 包，客户端必须正确处理 Retry Token、重新生成 Initial 包。最容易出错的地方是：**Retry 后的包号不能重置为零**。RFC 9000 §17.2.5.3 要求包号必须严格递增，即使经历了 Retry。quicX 的 `SendManager::ResetInitialPacketNumber()` 中有一段刻意保留的注释：清理 unacked/lost 状态，但**不触碰包号计数器**。这个"不做什么"比"做什么"更重要——我们在 35.6 会再回来讲这个故事。

**resumption** 和 **zerortt** 需要两次连接（`testcases.py` 中标记了 `needs_two_connections=True`）。第一次完成完整握手并保存 Session Ticket 到 `/tmp/session`，第二次用保存的会话恢复。0-RTT 测试还要验证 Early Data 是否被正确处理——服务端可能拒绝 0-RTT（比如因为 anti-replay 窗口过期），客户端必须能优雅地回退到 1-RTT 而不是挂死在那里等一个永远不会来的 0-RTT 确认。

**multiconnect** 是 handshake 的压力版本——`concurrent_clients=5`，5 个并发客户端同时发起握手，每个只传 1KB。这个场景暴露的不是单连接的协议正确性，而是服务端在并发压力下的资源管理：Initial 包的解密是 CPU 密集型操作，5 个同时到达的连接请求会不会导致超时？内存分配器能不能顶住？

**versionnegotiation** 通过客户端环境变量 `PREFERRED_VERSION=0x1a2a3a4a` 强制使用不存在的版本号，服务端必须返回 Version Negotiation Packet，客户端必须从中选择一个重新连接。**v2** 则反过来——双端 `QUIC_VERSION=0x6b3343cf` 要求使用 QUIC v2 完成完整握手和传输。两个场景合在一起考验版本协商的完整回路——拒绝不认识的版本、接受指定的版本、在协商过程中不陷入无限循环。

**chacha20** 通过双端 `CIPHER_SUITES=TLS_CHACHA20_POLY1305_SHA256` 强制使用 ChaCha20 密码套件传输 5MB 数据。大多数实现默认使用 AES-128-GCM（有 AES-NI 硬件加速），ChaCha20 的代码路径平时几乎不走。quicX 的 `tls_ctx.cpp` 中需要确保 ChaCha20 路径的头部保护、密钥更新、包号加密都和 AES 路径一样正确——这个场景就是把那些"备用路径"拉出来遛一遛。

这里有一个微妙之处：ChaCha20 和 AES-GCM 的头部保护算法不同（前者用 ChaCha20 本身，后者用 AES-ECB），如果实现在头部保护时硬编码了 AES 路径，ChaCha20 场景会在解密头部时就失败——这种 bug 极其难以诊断，因为日志只会告诉你"头部解析失败"，不会告诉你是头部保护算法选错了。

**keyupdate** 在传输 2MB 数据的过程中由客户端通过 `FORCE_KEY_UPDATE=1` 触发密钥更新。选择 2MB 是经过权衡的——足够让更新发生在传输中间阶段，又不至于耗时太长。难点在于**旧密钥的保留窗口**：更新后仍会收到用旧密钥加密的包，实现必须同时持有新旧两套密钥，根据包号范围选择正确的一套解密。

**connectionmigration** 要求客户端在传输 5MB 数据的过程中主动迁移到新地址。这个场景同时考验 PATH_CHALLENGE/PATH_RESPONSE 验证、CID 轮换、拥塞控制状态重置。quicX 为此专门开发了 `InitiateMigration()` API，在 `if_client.h` 中明确标注 "Used primarily for QUIC Interop Runner's connectionmigration test case"，保证互操作测试走的是与生产环境完全相同的代码路径，而不是某个只在测试中才走的旁路。

**rebind-port** 和 **rebind-addr** 模拟 NAT 重绑定——不是客户端主动迁移，而是网络中间设备改变了地址映射。两个场景都传输 5MB，区别在于 sim 是只改端口还是连 IP 也一起改。后者更具挑战性：IP 变化意味着路径特征可能完全不同，服务端必须判断这是攻击还是合法的 NAT 漂移，并在验证通过后重新探测路径参数。

**http3** 场景是唯一一个不使用 hq-interop 简化协议的测试。它传输三个不同尺寸的文件（10KB、100KB、1MB），要求双端使用完整的 HTTP/3 协议栈——QPACK 头部压缩、SETTINGS 帧交换、单向控制流建立。这个场景验证的不再是传输层，而是应用层映射：HTTP 语义能不能正确地编码到 QUIC 流上。

---

## 35.5 四种测试手段：各自扮演什么角色

互操作测试只是质量保障体系的一个维度。一个成熟的协议库需要四种测试手段协同工作，每种回答不同层次的问题。

**单元测试**回答"每个组件的逻辑是否正确"。quicX 有 140 多个单元测试，覆盖帧编解码、状态机转换、流控计算、拥塞控制响应等。优势是快速、确定、可重复，劣势是只验证单个组件在预设输入下的行为，无法发现组件交互时的问题。更致命的是，单元测试的输入是开发者设计的——开发者的盲区恰恰就是那些他没想到要测试的边界条件。

**模糊测试**回答"面对任意输入是否会崩溃"。quicX 的 12 个 LibFuzzer 目标分为两层：

帧层有两个目标。`frame_decode_fuzz` 对整个帧流做解码→重编码的 round-trip。`frame_fuzz` 更精细——它按帧类型 ID 从 0 到 24 逐个构造目标帧（Padding、Ping、ACK、ACK-ECN、ResetStream、StopSending、Crypto、NewToken、Stream 等全部 25 种），确保每种帧都至少经历一次完整的 Decode→Encode→Decode 循环，不会因为随机输入的概率偏好而漏掉低频帧类型。

包层有 10 个目标，逐个覆盖 Initial、Handshake、0-RTT、1-RTT、Retry、Version Negotiation 六种包类型以及长短头部解析和包号编解码。每个包类型的 fuzzer 测试两条路径：`DecodeWithoutCrypto`（只解析头部和结构）和 `DecodeWithCrypto`（完整的解密+解析）。

这种分层覆盖策略意味着任何一个字节位置的意外输入，都至少会被一个 fuzzer 触碰到。测试模式统一为 Decode→Encode→Re-Decode 的 round-trip——不只检查"不崩溃"，还验证了编解码的幂等性：同一个语义经过编码和解码后必须保持不变。

**基准测试**回答"性能是否发生了退化"。quicX 的测试分两个层次。

**组件级**用 Google Benchmark 框架，15 个基准文件定义了约 30 个参数化测试函数，覆盖的核心路径包括：

- Buffer 读写与 BufferChains 追加扁平化（256B/1KB/4KB/16KB 四档参数化）
- QPACK 全链路：静态索引解码、动态索引解码、字面量无索引解码、Huffman 编解码、编码器指令序列化、动态表条目复制
- AES-128-GCM 包级加解密（1KB/16KB/64KB 三档）
- ACK/MaxData/Stream 三种帧编解码、变长整数编解码（从单字节 0x3F 到八字节 0x3FFFFFFFFFFFFFFF）
- BlockMemoryPool 分配释放（2KB/4KB/16KB 三档块尺寸）
- 定时器——这部分测得最细：时间轮和 TreeMap 两种实现做了添加删除、批量操作、触发过期、混合延迟、模拟事件循环 tick 五种模式的对比，每种模式 100/1000/10000 三档任务量
- Reno 拥塞控制 OnAck/OnLoss 批量响应（1000 包/迭代）、RTT 更新与 PTO 间隔计算（1000 采样/迭代）
- HTTP/3 端到端请求响应全链路

**端到端**用 `PerformanceBenchmark` 测量三个维度：`BenchmarkLatency()` 发起 100 次串行请求统计 avg/P50/P95/P99/min/max 延迟分布；`BenchmarkThroughput()` 用 10 个并发连接下载 10MB 计算吞吐量（MB/s）；`BenchmarkConcurrency()` 用 50 个并发请求统计总完成时间和 RPS。

组件级基准防退化——每次提交后如果某个路径的 ns/op 突然跳升，CI 会报警；端到端基准测真实场景——延迟分布和吞吐才是用户关心的最终指标。

**互操作测试**回答"和其他实现是否能正确通信"。这是前三种测试都无法替代的——你的编解码可以完美、不会崩溃、性能极好，但如果你对某条 RFC 规则的理解和其他十一个实现不一致，连接仍然会失败。

四种手段的运行频率也不同。单元测试每次编译都跑，秒级完成；模糊测试在后台持续运行，以小时计；基准测试在每次合入主干时触发，分钟级；互操作测试在发布前和重大变更后手动触发，一次全矩阵跑完要几十分钟到几小时。频率越低的测试，发现问题的修复成本越高——但它们发现的问题，往往是高频测试根本无法触及的。

四种手段形成一个金字塔：单元测试覆盖最广、运行最快；模糊测试覆盖最深、对抗最强；基准测试覆盖性能维度；互操作测试覆盖正确性的最终验证。缺少任何一层，质量体系都有盲区。

---

## 35.6 协议库的成人礼：真实 bug 现场与全书收束

互操作测试最有价值的不是"通过了多少场景"，而是"暴露了多少你以为正确的理解"。从 quicX 的实践中，六个真实的 bug 现场可以说明这一点。

**Retry 后包号不能重置**。quicX 早期的实现在收到 Retry 包后会将包号计数器重置为零——毕竟"重新开始"嘛。但 RFC 9000 §17.2.5.3 明确要求包号必须严格大于 Retry 之前发出的最大包号。这个 bug 在自测中永远不会暴露——因为 quicX 的 server 和 client 用了相同的（错误的）逻辑，双方默契地接受了跳回零的包号。

直到和 quiche 握手时，quiche 果断拒绝了这个不合规的 Initial 包，连接立刻失败。修复后的 `ResetInitialPacketNumber()` 只清理 unacked/lost 状态，刻意保留包号计数器不动。代码注释里那句 "Do NOT reset pkt_num_largest_sent_ — The PN counter must continue incrementing after Retry per interop requirements" 是写给未来所有维护者的警告。

**Initial 包号至少两字节**。QUIC 的包号编码是变长的，理论上可以用单字节。但 quicX 在互操作中发现，部分实现对单字节包号的解析存在歧义——特别是当包号和连接 ID 长度字段相邻时，单字节编码容易导致解析错位。

最终 quicX 在 `packet_number.cpp` 的编码长度计算中加了一行硬约束：

```cpp
// RFC 9000: Initial packets should use at least 2-byte packet numbers
// to avoid ambiguity and ensure interoperability
return len < 2 ? 2 : len;
```

牺牲一个字节换取确定性，这是互操作测试教会我们的务实态度。

**连接迁移的 DCID 预先轮换**。quicX 在实现连接迁移时发现了一个微妙的时序问题：`OnPathResponse` 回调中不能重复轮换 DCID。如果客户端在调用 `InitiateMigration()` 时已经预先切换了目标 CID——这在 RFC 9000 §9.5 下是允许的——而 `OnPathResponse` 又触发了一次轮换，服务端就会收到一个它不认识的 CID，立刻发送 CONNECTION_CLOSE。

这个 bug 的根因是 RFC 对 CID 轮换时机的描述留有解释空间："An endpoint SHOULD use a new connection ID when it sends to a new peer address"，但没有说收到 PATH_RESPONSE 后是否应该再次轮换。两个独立实现对这句话的理解不同，只有在真实的跨实现迁移测试中才会暴露。

**bytes_in_flight 泄漏**。这个 bug 是在和 ngtcp2 做长时间传输（10MB）时暴露出来的——连接传了一段时间后吞吐量断崖式下降，拥塞窗口看起来已经满了，但网络上明明没有那么多未确认的数据。

追查 `send_control.cpp` 后发现了问题：当一个包先被标记为丢失（进入重传队列），后来又被 ACK 确认时（迟到的确认），`OnPacketAcked` 没有被调用，导致 `bytes_in_flight` 只增不减。拥塞控制认为管道里还有大量未确认字节，实际上那些字节早就被对端收到了——发送侧被自己制造的幽灵字节堵死。修复是加一个条件：

```cpp
// BUG FIX: Was missing this call, causing bytes_in_flight to leak
if (!task->second.is_lost) {
    congestion_control_->OnPacketAcked(...);
}
```

**丢失包的内存泄漏**。和 bytes_in_flight 是同一处代码中发现的姊妹问题。`send_control.cpp` 在检测到丢包并触发重传后，没有从 `unacked_packets_` 哈希表中移除原始包的记录。重传的数据以新包号重新进入 unacked 表，而旧记录就像幽灵一样永远留在那里——没人会再去确认它，也没人会去清理它。

短连接看不出问题，但互操作测试的长时间传输让这个泄漏积累到肉眼可见的程度。修复是在重传逻辑末尾加一行：

```cpp
// BUGFIX: Remove the lost packet from unacked_packets to prevent memory leak
// The retransmitted packet will be added with a new packet number
unacked_packets_[ns].erase(it);
```

**IPv4 优先的兼容性选择**。quicX 的 DNS 解析器在互操作测试中遇到了意料之外的问题：部分 QUIC 实现对 IPv6 的支持不完善，Docker 网络的 IPv6 配置也存在问题。好几个实现在 IPv6 下能握手但无法传输数据，换成 IPv4 就一切正常。最终 quicX 选择在 DNS 解析中优先返回 IPv4 地址——这不是协议层面的要求，而是工程现实中的妥协。互操作测试的目标是验证协议逻辑，不是验证 IPv6 栈的兼容性。

这六个 bug 有一个共同特征：**它们都不是"写错了"，而是"理解偏了"或者"路径没覆盖到"**。Retry 后的包号重置是对 RFC 的误读，Initial 包号的字节数是对互操作性的低估，DCID 轮换时序是对 RFC 模糊措辞的不同解读，bytes_in_flight 泄漏和内存泄漏是边缘路径上的遗漏。单元测试验证的是实现和设计的一致性，互操作测试验证的是设计和标准的一致性，长时间传输暴露的是那些只在累积效应下才显现的资源管理问题。

前者可以自己完成，后者必须借助外部的多样性和真实的负载。

互操作测试不是跑通一次就结束的仪式。每一个对端实现都在持续演进——quiche 升级了 BoringSSL、ngtcp2 重构了流控逻辑、quic-go 支持了新的扩展帧。上个月通过的测试，这个月可能因为对端的变更而失败。这意味着互操作矩阵不是一张静态的成绩单，而是一面持续照出你自己问题的镜子。

从卷一的内存池到卷七的互联互通，一个协议库经历了完整的成长弧线。内存池和 Buffer 解决了"怎么高效地搬运字节"；网络 IO 和线程模型解决了"怎么并发地处理连接"；握手和加密解决了"怎么安全地建立信任"；ACK 和丢包检测解决了"怎么在不可靠的网络上保证可靠"；拥塞控制解决了"怎么在共享的管道里公平地占用带宽"；流和流控解决了"怎么在一条连接里同时传输多路数据"；HTTP/3 解决了"怎么把应用层语义映射到传输层原语"；Metrics、Qlog 和上下文追踪解决了"怎么看见协议内部的运行状态"。

而互联互通测试，是最后一道关卡——它回答的问题不是"你能不能跑"，而是**"你能不能和这个世界上其他所有人一起跑"**。
