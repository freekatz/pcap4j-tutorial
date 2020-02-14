package org.pcap4j.sample;

import java.io.IOException;
import java.util.stream.Stream;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.util.NifSelector;
import org.pcap4j.util.Packets;

@SuppressWarnings("javadoc")
public class PacketStream {

  private static final String COUNT_KEY = PacketStream.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 5);

  private static final String READ_TIMEOUT_KEY = PacketStream.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = PacketStream.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  private PacketStream() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
    System.out.println("\n");

    PcapNetworkInterface nif;
    try {
      nif = new NifSelector().selectNetworkInterface();
    } catch (IOException e) {
      e.printStackTrace();
      return;
    }

    if (nif == null) {
      return;
    }

    System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

    try (PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
         // 此代码关键在下面这两行, 主要是告诉我们, 可以通过 Stream 来处理所有的包数据流
         /*
         Stream<PcapPacket> stream = handle.stream() 声明了一个专门存放 PcapPacket 对象的数据流对象
         其中 .stream() 方法是生成的串行流, pcap4j 只提供了串行流, 因为并行流会扰乱包的处理
         stream 可视为一个像 SQL 一样支持聚合操作的元素队列, 且这些操作都会返回相同的 stream  对象, 即所谓的 Pipelining
         除了 iterator 和 forEach 这样显式的外部迭代操作, stream 还可在 visitor(访问者) 模式下使用隐式的内部迭代操作
         聚合操作包括: filter, map, reduce, find, match, sorted 等等
          */
        Stream<PcapPacket> stream = handle.stream()) {
      stream.limit(COUNT).filter(Packets::containsUdpPacket).forEach(System.out::println);
    }
  }
}
