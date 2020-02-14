介绍
======

从本文开始将对 **Pcap4J**（下文简称为 **p4**）提供的样例代码进行注释讲解，期间还包括了对 **Pcap 原理**的解读

****

每篇文章讲解一个样例，目录如下：
目录
-----
- [Docker](#Docker)
  - [原理](#原理)
  - [步骤](#步骤)
  - [实现](#实现)
  - [总结](#总结)

****

Docker
------

#### 原理 #####

此代码算是之前学习的捕获数据包的小综合

#### 步骤 #####

略

#### 实现 #####

```java
package org.pcap4j.sample;

import com.sun.jna.Platform;
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
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.Packet;

@SuppressWarnings("javadoc")
public class Docker {

  private static final String COUNT_KEY = Docker.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 5);

  private static final String READ_TIMEOUT_KEY = Docker.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = Docker.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  // 设置 1MB 的缓存大小
  private static final String BUFFER_SIZE_KEY = Docker.class.getName() + ".bufferSize";
  private static final int BUFFER_SIZE =
      Integer.getInteger(BUFFER_SIZE_KEY, 1 * 1024 * 1024); // [bytes]

  // 之前说过, 这里 NANO 必定为 false
  private static final String TIMESTAMP_PRECISION_NANO_KEY =
      Docker.class.getName() + ".timestampPrecision.nano";
  private static final boolean TIMESTAMP_PRECISION_NANO =
      Boolean.getBoolean(TIMESTAMP_PRECISION_NANO_KEY);

  // 网卡 Name 即网卡的唯一标识码 uuid
  private static final String NIF_NAME_KEY = Docker.class.getName() + ".nifName";
  private static final String NIF_NAME = System.getProperty(NIF_NAME_KEY);

  // 是否在捕获包之前, 调用 waitForPing 函数
  private static final String WAIT_KEY = Docker.class.getName() + ".wait";
//  private static final boolean WAIT = Boolean.getBoolean(WAIT_KEY);
  private static final boolean WAIT = true; // 自行改为 true

  private Docker() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    String filter = args.length != 0 ? args[0] : "";

    System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
    System.out.println(BUFFER_SIZE_KEY + ": " + BUFFER_SIZE);
    System.out.println(TIMESTAMP_PRECISION_NANO_KEY + ": " + TIMESTAMP_PRECISION_NANO);
    System.out.println(NIF_NAME_KEY + ": " + NIF_NAME);
    System.out.println("\n");

    if (WAIT) { // WAIT 为 true 则调用此函数(会阻塞), 可以通过 ping 网关来结束此函数的阻塞
      waitForPing();
    }

    PcapNetworkInterface nif;
    if (NIF_NAME != null) {
      nif = Pcaps.getDevByName(NIF_NAME);
    } else {
//      nif = Pcaps.getDevByName("eth0"); // 网卡名, eth0 适用于 Unix 系统, 在 Win 平台需要改正
      nif = Pcaps.getDevByName("\\Device\\NPF_{C765F366-A156-43D7-AF26-B0824741C21E}");
    }

    System.out.println(nif.getName() + " (" + nif.getDescription() + ")");
    for (PcapAddress addr : nif.getAddresses()) { // 使用 for 循环适用于多 ip 的情况
      if (addr.getAddress() != null) {
        System.out.println("IP address: " + addr.getAddress());
      }
    }
    System.out.println("");

    // 使用 Builder 定义 handle, 可传入更多参数
    PcapHandle.Builder phb =
        new PcapHandle.Builder(nif.getName())
            .snaplen(SNAPLEN)
            .promiscuousMode(PromiscuousMode.PROMISCUOUS)
            .timeoutMillis(READ_TIMEOUT)
            .bufferSize(BUFFER_SIZE);
    if (TIMESTAMP_PRECISION_NANO) {
      phb.timestampPrecision(TimestampPrecision.NANO);
    }
    PcapHandle handle = phb.build();

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

    PcapStat ps = handle.getStats();
    System.out.println("ps_recv: " + ps.getNumPacketsReceived());
    System.out.println("ps_drop: " + ps.getNumPacketsDropped());
    System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
    if (Platform.isWindows()) {
      System.out.println("bs_capt: " + ps.getNumPacketsCaptured());
    }

    handle.close();
  }

  // 主要详细介绍一下这个函数
  private static void waitForPing() throws PcapNativeException, NotOpenException {
//    PcapNetworkInterface nif = Pcaps.getDevByName("eth0");
    PcapNetworkInterface nif = Pcaps.getDevByName("\\Device\\NPF_{C765F366-A156-43D7-AF26-B0824741C21E}");
    System.out.println(nif.getName() + " (" + nif.getDescription() + ")");
    for (PcapAddress addr : nif.getAddresses()) {
      if (addr.getAddress() != null) {
        System.out.println("IP address: " + addr.getAddress());
      }
    }
    System.out.println("");

    PcapHandle handle = nif.openLive(65536, PromiscuousMode.NONPROMISCUOUS, 10);
    // 专门捕获 icmp 数据包
    handle.setFilter("icmp", BpfCompileMode.OPTIMIZE);

    while (true) {
      Packet packet = handle.getNextPacket();
      if (packet == null) {
        continue;
      }
      // 如果捕获到的 icmp 数据包为回送请求或回送响应, 则停止捕获
      if (packet.contains(IcmpV4EchoPacket.class)) {
        break;
      }
    }

    handle.close();
  }
}
```

#### 总结 #####

到此为止，所有样例代码讲解完毕，此时我们已经有了独立开发 Pcap 程序的能力

接下来进入第 3 阶段：**开发基础功能模块函数**