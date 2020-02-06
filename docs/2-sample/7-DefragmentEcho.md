介绍
======

从本文开始将对 **Pcap4J**（下文简称为 **p4**）提供的样例代码进行注释讲解，期间还包括了对 **Pcap 原理**的解读

之前已经对 **p4** 的基本模块做了介绍，从现在开始介绍**协议、发包等进阶内容**，开始变得有趣了

****

每篇文章讲解一个样例，目录如下：
目录
-----
- [DefragmentEcho](#DefragmentEcho)
  - [原理](#原理)
  - [步骤](#步骤)
  - [实现](#实现)
  - [总结](#总结)

****

DefragmentEcho
------

#### 原理 #####

本样例代码示范了如何组装 IP 分片

在这之前，我们需要了解一下 **p4** 的Packet 接口：

- p4 中数据包主要由两部分组成, 一是 packet 对象, 二是 packet.builder 对象
-  packet 代表了数据包的 raw data 及其他信息
- 而 builder 则是代表了如何操作 packet, 任何对 packet 的操作都要通过 builder 来进行

#### 步骤 #####

- 打开 pcap 文件，读取 pcap 文件的离线数据包，将 IP 分片分别存入相应的映射中
- 组装分片，初始化原始数据包的 builder
- 将组装好的 IP 数据包上传到 builder 中
- 输出 builder.build() 结果

#### 实现 #####

```java
package org.pcap4j.sample;

import java.io.EOFException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.*;
import org.pcap4j.util.IpV4Helper;

@SuppressWarnings("javadoc")
public class DefragmentEcho {

  private static final String PCAP_FILE_KEY = DefragmentEcho.class.getName() + ".pcapFile";
  private static final String PCAP_FILE =
      System.getProperty(PCAP_FILE_KEY, "src/main/resources/flagmentedEcho.pcap");

  private DefragmentEcho() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    // 此代码为离线模式, 因此无需绑定网卡, 直接定义了一个用于处理离线 pcap 文件的 handle
    PcapHandle handle = Pcaps.openOffline(PCAP_FILE);

    // 定义了一个 Hash 映射, 键为短整型, 作为数据包的 ID, 值为 IPv4 分片数据包列表 (列表那肯定是可以迭代的了)
    Map<Short, List<IpV4Packet>> ipV4Packets = new HashMap<Short, List<IpV4Packet>>();
    // 定义了一个映射, 键为短整型, 作为数据包的 ID, 值为 Packet, 用于存放 IP 分片组装完成的原始数据包
    Map<Short, Packet> originalPackets = new HashMap<Short, Packet>();

    while (true) {
      try {
        // 上篇文章已经说过, 离线模式最好选择 GetNextPacketEx 来获取数据包
        Packet packet = handle.getNextPacketEx();
        /*
        1. packet.get(IpV4Packet.class): 此为 packet 的 get 方法, 传入的是想要获取对象的类名
        get 方法遍历此 packet 的有效载荷得到想要获取的特定的对象, 比如这行代码就会获取 packet 中包含的 IPv4 类型的包
        如一个包中有找到多个需要的对象,只会返回最外面的一层,比如一个 IPsec 包中包含了两层 IPv4 包装, 那么 get 方法只会返回最外面的一层
        当然, 也有直接输出多层的方法, 遇到再说
        2. .getHeader() 方法则是返回包对象的头部, 简单
        3. .getIdentification() 获取 IPv4 包的标识
         */
        Short id = packet.get(IpV4Packet.class).getHeader().getIdentification();
        if (ipV4Packets.containsKey(id)) { // 如果 IP 包的标识一样, 即同属于一个 IP 分片, 则直接添加到同一个列表中
          ipV4Packets.get(id).add(packet.get(IpV4Packet.class));
        } else { // 如果不一样, 则新增一个映射 <Short, List<IpV4Packet>>()
          List<IpV4Packet> list = new ArrayList<IpV4Packet>();
          list.add(packet.get(IpV4Packet.class));
          ipV4Packets.put(id, list); // IPv4 数据包
          originalPackets.put(id, packet); // 原始数据包, id 与 IPv4 的 id 一样
          // 特别注意: 此时 originalPackets 中的数据包并不是真正的原始数据包, 而是 IP 分片的<b>第一个<b/>
        }
      } catch (TimeoutException e) {
        continue;
      } catch (EOFException e) {
        break;
      }
    }
    for (Short id : ipV4Packets.keySet()) {
      List<IpV4Packet> list = ipV4Packets.get(id);
      // 由于同一个列表的数据包属于同一个 IP 分片, 故下面的代码则是将这些分配整理到一起
      // IpV4Helper 是 pcap4j 的工具类, 它提供了两个静态方法, 分别是: fragment 和 defragment, 即分片与组装
      final IpV4Packet defragmentedIpV4Packet = IpV4Helper.defragment(list);

      // 下面的是此代码的核心部分:
      /*
      1. Packet.Builder 与之前说过的 PcapHandle.Builder 不同, 它是一个可迭代的构建器对象, 此构建器用来构建和操纵包含在此数据包中的各种协议的包对象
      如 originalPackets.get(id).getBuilder() 就是从原始数据包映射中得到一个数据包, 并使用 .getBuilder() 方法得到此数据包的构建器
      2. builder 对象可使用各种方法操纵数据包, 如 Packet (链路层) 的 builder 可操纵整个 Packet 上层 (即链路层及链路层之上)的数据包, 而
      IpPacket (网络层) 的 builder 可操纵整个 IpPacket 上层 (即网络层及网络层之上)的数据包
      3. .getLowerLayerOf 方法即得到下层的具体协议的构建器, 再使用 .payloadBuilder 方法将传入的 builder 上传或是设置到 builder 中
      如果不设置则 builder 只会构建到网络层, 设置之后才可以构建到最上层 (此代码为 IcmpV4)
      4. .build 方法则是构建数据包, 返回 PcapPacket 对象
      5. 编写程序时一定要注意 payload 和 builder 类型的一致性, 试想一下, 给一个 IpV4 构建器 payload 一个 Icmp 的构建器肯定是不行的
       */
      Packet.Builder builder = originalPackets.get(id).getBuilder();
      builder
          .getLowerLayerOf(IpV4Packet.Builder.class)
          .payloadBuilder(new SimpleBuilder(defragmentedIpV4Packet));

      System.out.println(builder.build());
    }
    handle.close();
  }
}

```



#### 总结 #####

本文通过组装 IP 分片的示例，学到了：

1. 数据包捕获的离线模式 （Offline），及通过 GetPacketEx 来读取数据包
2. 组装 IP 分片，使用了 IpV4Helper 提供的静态方法可以组装和分片
3. 初步认识了 Packet 接口定义的 Builder 构建器对象，以及如何通过各类的 Builder 来构建数据包
4. 重点认识了 getLowerLayerOf、payloadBuilder、build 三个方法