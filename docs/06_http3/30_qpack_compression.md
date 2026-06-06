# 30. QPACK：乱序世界里的头压缩引擎

HEADERS 帧携带的头部字段要被压缩——这一点没有争议。HTTP/2 用 HPACK 做到了极高的压缩率，靠的是编码端和解码端共享一张动态表，用索引号代替完整的名值对。但 HPACK 的正确性建立在一个隐含前提上：TCP 保证有序交付。QUIC 打破了这个前提——流与流之间可以乱序到达。在一个编码端和解码端可能看到不同操作顺序的世界里，如何让双方的压缩字典保持一致？QPACK 就是对这个问题的完整回答。

---

## 30.1 HPACK 在有序交付世界里的成立条件

HPACK（RFC 7541）是 HTTP/2 的头部压缩机制。它的核心思路是维护一张编码端和解码端共享的**动态表**：编码端把频繁出现的头部字段插入表中，之后只需发送一个索引号（可能只有 1 字节），接收端用同一个索引号从本地的动态表里取出完整的名值对。当 HTTP 头部在请求之间大量重复时——例如每个请求都带 `user-agent`、`accept-encoding`、`cookie`——压缩率可以非常高。

这套机制的正确性建立在一个隐含前提上：**编码端和解码端看到的操作序列必须完全一致**。如果编码端先插入条目 A 再插入条目 B，解码端也必须按同样的顺序看到 A 和 B 的插入——否则同一个索引号在两端可能指向不同的条目。

HTTP/2 天然满足这个前提。它跑在 TCP 之上，所有 HEADERS 帧在 TCP 字节流中有确定的先后顺序。即使多条 HTTP/2 流在逻辑上并发，它们的帧在 TCP 里仍然是单文件排列的。编码端按什么顺序发送插入指令，解码端就按什么顺序接收——动态表在两端永远同步。

一句话总结：HPACK 的安全性建立在"TCP 保证有序"这个地基之上。地基一旦移走，上面的建筑就会坍塌。

---

## 30.2 乱序交付为什么会让头压缩变危险

QUIC 的 Stream 是独立交付的。Stream A 的数据可能比 Stream B 先到达解码端，即使 Stream B 的 HEADERS 帧在编码端先发送。这个特性是 QUIC 消除队头阻塞的核心优势——但它恰好摧毁了 HPACK 的安全假设。

设想一个具体场景。编码端在 Stream 1 的 HEADERS 帧中把 `x-request-id: abc123` 插入动态表，得到索引 62。随后在 Stream 3 的 HEADERS 帧中引用索引 62。如果 Stream 3 的数据比 Stream 1 先到达解码端，解码端此刻的动态表里还没有索引 62 的条目。两种结果都很糟糕：

1. **解码失败**：引用了不存在的索引号，程序报错或崩溃。这是显式的错误，至少容易被发现。
2. **索引错位**：如果解码端的动态表因其他操作恰好在索引 62 存放了不同的条目，引用会指向错误的值。更危险的是，这种错误是**静默的**——后续所有引用都可能指向错误的条目，而双方都不知道。

QUIC 不可能为了兼容 HPACK 而放弃乱序交付——那等于退回 TCP 的老路，丢掉队头阻塞消除这个核心价值。因此问题变成：如何设计一套新的头压缩机制，既保留动态表的压缩收益，又不依赖有序交付。

---

## 30.3 QPACK 的三重设计：分离指令流、Required Insert Count 与 Base

QPACK（RFC 9204）用三个层层递进的设计解决乱序问题。

### 设计一：将动态表更新从 Header Block 中分离出来

HPACK 把动态表更新和头部引用混在同一个 HEADERS 帧中——编码端在帧里同时做"插入新条目"和"引用已有条目"两件事。QPACK 的第一个改变是**把插入操作搬到独立的 Encoder Stream 上**。

Encoder Stream 是一条单向流（流类型 `0x02`），它有自己的偏移量和有序保证——同一条流上的字节按发送顺序到达。编码端通过 Encoder Stream 发送四种指令：

| 指令 | 首字节模式 | 作用 |
|------|-----------|------|
| Set Dynamic Table Capacity | `001xxxxx`（5-bit 前缀） | 更新动态表容量上限 |
| Insert With Name Reference | `1Txxxxxx`（6-bit 前缀，T=静态/动态） | 用已有条目的名称插入新条目 |
| Insert Without Name Reference | `01xxxxxx`（6-bit 前缀） | 用字面量名称和值插入新条目 |
| Duplicate | `000xxxxx`（5-bit 前缀） | 复制一个即将被驱逐的条目到表头 |

Header Block（在 HEADERS 帧中）只做**引用**，不做插入。引用一个动态表条目的前提是：该条目已经通过 Encoder Stream 的插入指令到达了解码端。如果还没到达——不是解码错误，而是等它到了再解码。

解码端通过 **Decoder Stream**（流类型 `0x03`）向编码端反馈三种信息：

| 指令 | 首字节模式 | 作用 |
|------|-----------|------|
| Section Acknowledgment | `1xxxxxxx`（7-bit 前缀） | 确认某个 Header Block 已成功解码 |
| Stream Cancellation | `01xxxxxx`（6-bit 前缀） | 通知编码端某条流被取消 |
| Insert Count Increment | `00xxxxxx`（6-bit 前缀） | 告知编码端解码端已处理了更多插入指令 |

反馈的意义在于：编码端可以根据反馈判断哪些动态表条目已被对端确认，从而安全地驱逐旧条目腾出空间。

### 设计二：Required Insert Count——解码器的安全卫兵

把插入操作分离到 Encoder Stream 上解决了"操作顺序"问题，但引入了新问题：当一个 Header Block 到达解码端时，它引用的动态表条目可能还在 Encoder Stream 的路上。QPACK 用 **Required Insert Count（RIC）** 解决这个时序问题。

每个 Header Block 的前缀中携带一个 RIC：解码这个 Header Block 需要动态表中**至少**已经收到这么多条插入指令。如果解码端的动态表还没有收到足够的插入指令，它不会尝试解码——而是**阻塞**这个 Header Block，等待 Encoder Stream 的数据到达后再继续。

阻塞和错误的区别是关键的：阻塞是可恢复的（等数据到了就能继续），错误是不可恢复的。QPACK 用阻塞替代了错误，把一个正确性问题转化为了延迟问题。

RIC 的线上编码使用 wrap-around 算法减少字节开销（RFC 9204 §4.5.1）。编码端的公式：

```
MaxEntries = floor(MaxTableCapacity / 32)

if ReqInsertCount == 0:
    EncodedInsertCount = 0
else:
    EncodedInsertCount = (ReqInsertCount mod (2 * MaxEntries)) + 1
```

解码端需要从 `EncodedInsertCount` 和自己已知的 `TotalNumberOfInserts` 反推出真实的 RIC：

```
FullRange = 2 * MaxEntries
if EncodedInsertCount == 0:
    ReqInsertCount = 0
else:
    MaxValue = TotalNumberOfInserts + MaxEntries
    MaxWrapped = floor(MaxValue / FullRange) * FullRange
    ReqInsertCount = MaxWrapped + EncodedInsertCount - 1
    if ReqInsertCount > MaxValue:
        ReqInsertCount -= FullRange
```

为什么要这么复杂？因为 RIC 是单调递增的，直接编码会越来越大。取模编码把值限制在 `[0, 2*MaxEntries)` 范围内，通常只需 1-2 字节。解码端利用自己已知的插入总数来消除歧义。

### 设计三：Base Index——编码时刻的快照

Header Block 前缀中还携带一个 **Base**：编码这个 Header Block 时动态表的参考基准。动态表引用使用**相对于 Base 的索引**而非绝对索引，这样 Header Block 的引用不受后续插入的影响。

对于编码时已经存在的条目，使用普通的相对索引：`relative_index = base - 1 - absolute_index`。对于编码时同步插入的条目（绝对索引 ≥ base），使用 Post-Base 索引：`post_base_index = absolute_index - base`。Base 相对于 RIC 编码，只需一个符号位（S）和一个 Delta 值：

```
if S == 0:  Base = ReqInsertCount + DeltaBase
if S == 1:  Base = ReqInsertCount - DeltaBase - 1
```

三个设计叠加的效果是：Encoder Stream 保证插入操作有序到达，RIC 保证 Header Block 只在条件满足时才被解码，Base 保证引用不受后续操作干扰。一个"乱序世界里的安全字典"就这样被构建出来了。

---

## 30.4 静态表、动态表与 Huffman：QPACK 的三张压缩牌

QPACK 的压缩能力来自三种手段：静态表负责高频词汇，动态表负责连接内重复，Huffman 编码负责字面量的最后一英里压缩。

### 静态表：99 个预定义条目

QPACK 的静态表（RFC 9204 Appendix A）包含 99 个预定义的名值对，覆盖了 HTTP/3 流量中出现频率最高的头部字段。与 HPACK 的 61 个条目相比，QPACK 增加了更多实际流量中常见的值：

| 索引范围 | 内容 |
|----------|------|
| 0 | `:authority`（空值） |
| 1 | `:path` = `/` |
| 15–21 | `:method` = CONNECT / DELETE / GET / HEAD / OPTIONS / POST / PUT |
| 22–23 | `:scheme` = http / https |
| 24–28, 63–71 | `:status` = 103 / 200 / 304 / 404 / 503 / 100 / 204 / 206 / 302 / 400 / 403 / 421 / 425 / 500 |
| 44–54 | `content-type` 的多种 MIME 类型 |
| 56–58 | `strict-transport-security` 的常见策略 |

静态表的索引从 0 开始（HPACK 从 1 开始），全部内容在连接建立前就已确定，两端不需要任何同步。当一个 Header Block 引用静态表时，编码为 `11xxxxxx`（Indexed — Static），只需 1-2 字节即可表示一个完整的头部字段。

quicX 的 `StaticTable` 用 Singleton 模式实现，内部维护三套查找结构：`headeritem_vec_`（按索引顺序的 `vector<HeaderItem>`）、`headeritem_index_map_`（name+value → 索引的哈希表）、`headeritem_name_map_`（name → 最小索引的哈希表）。三种查找方式分别服务于按索引取回（解码）、精确匹配（编码优先路径）和仅名称匹配（退化路径）。

### 动态表：连接期间的学习记忆

静态表覆盖的是全局高频词汇，每条连接特有的高频头部——如特定的 Cookie 值、自定义的 `x-request-id`——需要动态表来压缩。

quicX 的 `DynamicTable` 用 `std::deque<HeaderItem>` 实现。新条目 `push_front`（索引 0），旧条目从尾部驱逐。每个条目的大小按 RFC 7541 §4.1 的公式计算：`name.length() + value.length() + 32`（32 字节是估算的内存管理开销）。

插入新条目时（`AddHeaderItem`），如果动态表空间不足，先从尾部循环驱逐最旧的条目（`EvictEntries`），再把新条目 `push_front`。由于 `push_front` 使所有旧条目的相对位置后移一位，`headeritem_index_map_` 中所有现有索引需要 +1——这是一个 O(n) 操作。对于小动态表（典型配置 128-256 个条目）代价可以接受，大动态表下则有性能隐患。

`DuplicateEntry` 实现 RFC 9204 §2.2.1 的 Duplicate 指令：把一个即将被驱逐的条目复制到表头，延长它的生命周期。这在高频条目快要被淘汰时很有用——复制比重新插入更省带宽，因为 Duplicate 指令只需一个索引号。

`GetInsertCount()` 返回自表创建以来的总插入次数（`total_insert_count_`），这个值单调递增，用于 RIC 的 wrap-around 编解码。

### Huffman 编码：字面量的最后一英里

当一个头部字段既不在静态表也不在动态表中时，名称和值需要以字面量形式传输。Huffman 编码可以把常见的 ASCII 字符（a-z、0-9）从 8 bit 压缩到 5-6 bit，对纯文本头部通常能节省 20%-30% 的字节。

quicX 的 `HuffmanEncoder` 也是 Singleton 模式，使用 RFC 7541 Appendix B 的静态码表（257 个条目：256 个 ASCII 字符 + EOS）。编码前先调用 `ShouldHuffmanEncode(input)` 逐字符累加编码后的比特数——只有编码后更短时才使用 Huffman，避免对已经很紧凑的二进制值做无效编码。

解码端不能逐 bit 遍历 Huffman 树（太慢），quicX 使用**预计算的 256×16 状态转移表**（`HuffmanTable`）。每个状态处理 4 bit（一个 nibble），每字节只需两次查表（高 4 bit + 低 4 bit）。状态转移表的每个节点包含四个字段：`next`（下一状态）、`emit`（是否输出字符）、`symbol`（输出的字符）、`ending`（是否为合法结束位置）。整张表占约 16 KB，以空间换时间，实现 O(n) 的线性解码。

### 七种 Header Block 表示

三种压缩手段在编码时通过七种表示类型混合使用：

| 首字节模式 | 含义 | 前缀长度 |
|-----------|------|---------|
| `11xxxxxx` | Indexed — Static（静态表精确匹配） | 6 bit |
| `10xxxxxx` | Indexed — Dynamic（动态表精确匹配） | 6 bit |
| `0101xxxx` | Literal Name Ref — Static（静态表名称匹配 + 字面量值） | 4 bit |
| `0100xxxx` | Literal Name Ref — Dynamic（动态表名称匹配 + 字面量值） | 4 bit |
| `001xxxxx` | Literal — No Name Ref（字面量名称 + 字面量值） | 3 bit |
| `0001xxxx` | Post-Base Indexed（Post-Base 动态表精确匹配） | 4 bit |
| `0000xxxx` | Post-Base Literal Name Ref（Post-Base 名称匹配 + 字面量值） | 4 bit |

编码端的选择策略是优先级递减：**静态表精确匹配 > 静态表名称匹配 > 动态表精确匹配 > 动态表名称匹配 > 字面量**。匹配程度越高，编码后越短。

---

## 30.5 quicX 的 QPACK 编解码器：从 Header Map 到 Wire Bytes

quicX 的 QPACK 核心是 `QpackEncoder` 类（824 行），它同时承担编码和解码两个职责——一个类兼任两个角色，违反单一职责原则，但简化了动态表的共享。

### 编码路径

`Encode()` 接收一组 HTTP 头部字段（`unordered_map<string, string>`），输出 QPACK 编码后的字节流。完整流程分为三步：

**第一步：写 Header Block 前缀**。调用 `WriteHeaderPrefix()` 写入 RIC 和 Delta Base。当前实现把 RIC 设为 `dynamic_table_.GetInsertCount()`（全部插入数），Base 设为 RIC——这意味着不使用 Post-Base 引用。这个策略简化了实现，但可能导致不必要的阻塞：即使 Header Block 只引用了静态表条目，解码端仍然要等待动态表追上 RIC 才能开始解码。

**第二步：伪头部优先编码**。按 `:method` → `:scheme` → `:authority` → `:path` → `:status` 的顺序先处理伪头部，再处理普通头部。这与 RFC 9114 §4.3 的要求一致——所有伪头部必须出现在 Header Block 的最前面。

**第三步：逐个头部字段选择最优编码**。对每个字段，按优先级递减尝试：

1. 静态表精确匹配（name + value 都命中）→ `Indexed — Static`
2. 静态表名称匹配（只有 name 命中）→ `Literal Name Ref — Static` + 编码 value
3. 动态表精确匹配 → `Indexed — Dynamic`，使用相对索引 `base - 1 - absolute_index`
4. 动态表未命中但启用动态表 → 插入新条目 + 通过 `instruction_sender_` 回调发送 Encoder Instruction
5. 最终兜底 → `Literal — No Name Ref`，名称和值都以字面量形式编码

值的编码（`EncodeString`）会先调用 `HuffmanEncoder::ShouldHuffmanEncode()` 判断是否使用 Huffman，然后以 `[H|长度(7-bit 前缀)] [数据]` 的格式写入。

### 解码路径

`Decode()` 是编码的逆过程。

**第一步：读 Header Block 前缀**。`ReadHeaderPrefix()` 从前缀中解码 RIC 和 Base。解码 RIC 需要用到 wrap-around 反算逻辑——结合解码端已知的 `TotalNumberOfInserts` 和 `MaxEntries` 来消除取模歧义。

**第二步：阻塞检查**。如果 `required_insert_count > dynamic_table_.GetInsertCount()`，说明 Encoder Stream 的数据还没到齐，直接返回失败。上层的 `ReqRespBaseStream` 会把这次解码操作封装为闭包，注册到 `BlockedRegistry` 中等待唤醒。

**第三步：逐字段解码**。循环读取每个字节的高位比特模式，分发到七种表示类型的解码分支。动态表引用需要做索引转换：普通引用用 `absolute_index = base - 1 - relative_index`，Post-Base 引用用 `absolute_index = base + post_base_index`。

### 编码器指令的编解码

`EncodeEncoderInstructions()` 将编码端的动态表操作（插入、复制、设容量）序列化为 Encoder Stream 字节。`DecodeEncoderInstructions()` 在接收端解析这些指令，根据首字节比特模式分发到四种指令的处理逻辑，执行对应的动态表操作（`AddHeaderItem`、`DuplicateEntry`、`UpdateMaxTableSize`）。

### 与请求/响应流的集成

`ReqRespBaseStream` 是请求/响应流的基类，也是 QPACK 的实际调用者。发送头部时：

```
HTTP headers → QpackEncoder::Encode() → 编码后字节 → HeadersFrame → QUIC 流
```

接收头部时：

```
QUIC 流 → FrameDecoder → HeadersFrame → QpackEncoder::Decode() → HTTP headers
                                            ↓ (RIC 不满足)
                                    BlockedRegistry::Add(key, retry_closure)
                                            ↓ (Encoder Stream 数据到达)
                                    NotifyAll() → retry → 成功 → Section Ack
```

`header_block_key_` 使用 `(stream_id << 32) | section_number` 编码，作为 64-bit 唯一标识符在 `BlockedRegistry` 和 Section Ack 中传递。

---

## 30.6 阻塞的代价与权衡：QPACK_BLOCKED_STREAMS 的意义

QPACK 用"阻塞"替代了"错误"，把正确性问题转化为延迟问题。但阻塞本身也有代价。

### 阻塞的场景与代价

当一个 Header Block 引用了动态表条目，但 Encoder Stream 的插入指令还没到达解码端时，这个 Header Block 的解码被挂起。挂起意味着这条请求流被阻塞——无法处理请求头、无法路由到 Handler、无法开始处理业务逻辑。如果高并发场景下大量流同时被阻塞，HTTP/3 宣称的"消除队头阻塞"优势就会被 QPACK 的阻塞行为部分抵消。

这里有一个讽刺的对称性：**HPACK 永远不会阻塞任何流（因为 TCP 保证有序），但整条 TCP 连接会因为一个包的丢失而队头阻塞所有流；QPACK 可能阻塞个别流（等待 Encoder Stream 数据），但其他流完全不受影响。** QPACK 用"可控的少量阻塞"换来了"消除全局队头阻塞"——这是一笔值得做的交易。

### QPACK_BLOCKED_STREAMS：给阻塞设上限

为了防止阻塞失控，QPACK 引入了 `QPACK_BLOCKED_STREAMS` 参数（通过 SETTINGS 帧协商）。这个参数规定了同一时刻最多允许多少条流处于阻塞状态。编码端在编码前必须检查：如果当前已阻塞的流数量已达上限，就不能再使用可能导致阻塞的动态表引用——只能退化为静态表引用或字面量编码。

两个极端策略揭示了设计空间的边界：

- **永不使用动态表**（`QPACK_MAX_TABLE_CAPACITY = 0`）：不会阻塞任何流，但完全放弃动态表的压缩收益。退化为"静态表 + Huffman"模式。
- **激进使用动态表**（大容量 + 高阻塞上限）：最大化压缩收益，但可能导致大量流同时被阻塞，在网络抖动时加剧延迟。

实际部署中大多数实现选择中间路线——小到中等容量的动态表加上适度的阻塞上限，在压缩率和延迟之间取平衡。

### quicX 的 BlockedRegistry

quicX 用 `QpackBlockedRegistry` 管理阻塞状态。它的核心是一张 pending 表（`unordered_map<uint64_t, function<void()>>`），key 是 `header_block_key_`，value 是解码操作的重试闭包。

- `SetMaxBlockedStreams(n)`：从 SETTINGS 参数初始化上限
- `CanAddBlocked()`：编码前检查 `pending_.size() < max_blocked_streams_`
- `Add(key, retry_closure)`：注册一个阻塞的解码操作
- `NotifyAll()`：Encoder Stream 数据到达并更新动态表后，批量唤醒所有被阻塞的解码操作
- `Ack(key)`：Section Ack 到达后移除对应的阻塞记录
- `Remove(key)`：Stream Cancellation 到达后移除记录

`NotifyAll()` 的语义是"盲唤醒"——它不检查每个闭包的 RIC 是否已满足，而是让所有闭包重新尝试解码。如果某个 Header Block 的 RIC 仍然不满足，它会再次注册到 pending 表中。这个设计牺牲了一点效率（可能有无效的重试），但极大简化了实现——不需要为每个闭包维护精确的 RIC 状态。

### 从 HPACK 到 QPACK 的设计弧线

回望这条演进路径，核心思想很清晰：HPACK 把所有赌注压在传输层的有序性上——一旦传输层不再保证有序，赌注就输了。QPACK 的回应不是"重新发明有序性"，而是承认乱序是现实，在乱序的世界里用分离指令流、RIC 安全卫兵和 Base 快照三层机制重建字典一致性。它不追求"永远不阻塞"，而是接受"偶尔阻塞"作为代价，用 `QPACK_BLOCKED_STREAMS` 把代价控制在可接受的范围内。

这不仅仅是一个头压缩算法的迭代，更是一个"从依赖有序到拥抱乱序"的协议设计范式转变。
