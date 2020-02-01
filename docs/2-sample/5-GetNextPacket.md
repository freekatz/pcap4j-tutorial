介绍
======

从本文开始将对 **Pcap4J**（下文简称为 **p4**）提供的样例代码进行注释讲解，期间还包括了对 **Pcap 原理**的解读

****

GetNextPacket
------

#### 原理 #####

#### 步骤 #####

- 初始化、通过 builder 构建 handle
- 处理、编译过滤规则
- 捕获数据包并输出
- 捕获完毕，输出统计信息

#### 实现 #####

```java
package org.pcap4j.sample;

import com.sun.jna.Platform;
import java.io.IOException;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class GetNextPacket {

  private static final String COUNT_KEY = GetNextPacket.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 5);

  private static final String READ_TIMEOUT_KEY = GetNextPacket.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = GetNextPacket.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  // 设置缓冲区大小, 单位为 字节, 在 Dump 的文章中已经提到, 使用 GetNextPacket 捕获数据包最好先设置缓冲区以防丢包
  private static final String BUFFER_SIZE_KEY = GetNextPacket.class.getName() + ".bufferSize";
  private static final int BUFFER_SIZE =
      Integer.getInteger(BUFFER_SIZE_KEY, 1 * 1024 * 1024); // [bytes]

  private static final String TIMESTAMP_PRECISION_NANO_KEY =
      GetNextPacket.class.getName() + ".timestampPrecision.nano";
  private static final boolean TIMESTAMP_PRECISION_NANO =
      Boolean.getBoolean(TIMESTAMP_PRECISION_NANO_KEY);

  // 初始化网卡名字, 即网卡标识, 为 null
  private static final String NIF_NAME_KEY = GetNextPacket.class.getName() + ".nifName";
  private static final String NIF_NAME = System.getProperty(NIF_NAME_KEY);

  private GetNextPacket() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    String filter = args.length != 0 ? args[0] : "";

    System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
    System.out.println(BUFFER_SIZE_KEY + ": " + BUFFER_SIZE);
    System.out.println(TIMESTAMP_PRECISION_NANO_KEY + ": " + TIMESTAMP_PRECISION_NANO);
    System.out.println(NIF_NAME_KEY + ": " + NIF_NAME);
    System.out.println("\n");

    PcapNetworkInterface nif;
    if (NIF_NAME != null) {
      nif = Pcaps.getDevByName(NIF_NAME);
    } else {
      try {
        nif = new NifSelector().selectNetworkInterface();
      } catch (IOException e) {
        e.printStackTrace();
        return;
      }

      if (nif == null) {
        return;
      }
    }

    System.out.println(nif.getName() + " (" + nif.getDescription() + ")");
    // 以下代码为输出网卡的 IP, 包括 IPv4 以及 IPv6
    for (PcapAddress addr : nif.getAddresses()) {
      if (addr.getAddress() != null) {
        System.out.println("IP address: " + addr.getAddress());
      }
    }
    System.out.println("");

    PcapHandle.Builder phb =
        new PcapHandle.Builder(nif.getName())
            .snaplen(SNAPLEN)
            .promiscuousMode(PromiscuousMode.PROMISCUOUS)
            .timeoutMillis(READ_TIMEOUT)
            .bufferSize(BUFFER_SIZE);
    if (TIMESTAMP_PRECISION_NANO) {
      phb.timestampPrecision(TimestampPrecision.NANO);
    }

    try (PcapHandle handle = phb.build()) {
      handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

      int num = 0;
      while (true) {
        Packet packet = handle.getNextPacket();
        if (packet == null) {
          continue;
        } else {
          System.out.println(packet);
          num++;
          if (num >= COUNT) {
            break;
          }
        }
      }

      // 以上代码之前都已经说过, 不再重复
      // 关于 PcapStat 类也没什么好说的, 它只统计了下面输出的这四个数值, 样例代码全写出来了,期待作者增加更多的统计属性
      // 其实我挺想贡献一下的, 在这里立下个 Flag 了
      PcapStat ps = handle.getStats();
      System.out.println("ps_recv: " + ps.getNumPacketsReceived());
      System.out.println("ps_drop: " + ps.getNumPacketsDropped());
      System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
      if (Platform.isWindows()) {
        System.out.println("bs_capt: " + ps.getNumPacketsCaptured());
      }
    }
  }
}

```



#### 总结 #####

本代码虽然比较长，但是都是之前文章介绍过的内容，并没有新知识