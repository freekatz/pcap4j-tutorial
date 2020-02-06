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
