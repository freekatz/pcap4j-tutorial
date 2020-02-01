介绍
======

从本文开始将对 **Pcap4J**（下文简称为 **p4**）提供的样例代码进行注释讲解，期间还包括了对 **Pcap 原理**的解读

****

Dump
------

#### 原理 #####

这里无需深究 .pcap 文件的格式，只介绍需要关注的重点内容

- 网卡的**监听模式**（[引自：维基百科](https://zh.wikipedia.org/wiki/监听模式)）

> **监听模式**（monitor mode），或 **RFMON**（Radio Frequency MONitor），是指[无线](https://zh.wikipedia.org/wiki/无线网络)[网卡](https://zh.wikipedia.org/wiki/网卡)可以接收所有经过它的数据流的工作方式，对应于[IEEE 802.11](https://zh.wikipedia.org/wiki/IEEE_802.11)网卡的其他模式，诸如Master（[路由器](https://zh.wikipedia.org/wiki/路由器)）、Managed（普通模式的网卡）、[Ad-hoc](https://zh.wikipedia.org/wiki/Ad_hoc网络)等。监听模式不区分所接收[数据包](https://zh.wikipedia.org/wiki/資料包)的目标[MAC地址](https://zh.wikipedia.org/wiki/MAC地址)，这点和[混杂模式](https://zh.wikipedia.org/wiki/混杂模式)类似。然而，**和混杂模式不同的是，监听模式的不需要和[无线接入点](https://zh.wikipedia.org/wiki/无线接入点)（AP）或 Ad-hoc网络建立连接。**监听模式是无线网卡特有的特殊模式，而混杂模式应用于有线网卡和无线网卡。

- Loop（观察者模式）及 getNextPacket：其他抓包方法遇到再说
  - Loop 是无限循环捕获数据包，直到达到了设置的条件，每抓到一个包就自动调用回调函数 gotPacket
  - getNextPacket 是一个可阻塞的**异步抓包方法**，每抓到一个包返回一个包，相比于 Loop 你可以**更加自由地处理数据包**：既可以直接回调，也可以使用更复杂的逻辑进行处理，处理完一个包之后继续抓下一个包（所以使用这个函数，在特定情况下，比如处理逻辑时间复杂度比较大的时候，需要设置 handle 的**缓冲区**来保证不丢包）

#### 步骤 #####

- 初始化、通过 builder 构建 handle
- 处理、编译过滤规则
- 捕获数据包，及进行其他操作
- 捕获完毕，通过 dump 得到 .pcap 文件

#### 实现 #####

```java
package org.pcap4j.sample;

import java.io.IOException;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class Dump {

  // 设置 COUNT 常量，代表本次捕获数据包的数目，其中 -1 代表一直捕获
  private static final String COUNT_KEY = Dump.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 5);

  // 等待读取数据包的时间（以毫秒为单位）, 必须非负 ,其中 0 代表一直等待直到抓到包为止
  private static final String READ_TIMEOUT_KEY = Dump.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  // 要捕获的最大数据包大小（以字节为单位）
  private static final String SNAPLEN_KEY = Dump.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  // 时间戳精度是否达到纳秒级
  private static final String TIMESTAMP_PRECISION_NANO_KEY =
      Dump.class.getName() + ".timestampPrecision.nano";
  /*
  由于多次出现基本数据类型的包装器类的 get*() 方法,所以在这里说一下, 以 Boolean 为例:
  本代码得到的 TIMESTAMP_PRECISION_NANO 必定为 false, 因为 TIMESTAMP_PRECISION_NANO_KEY 不是系统属性且值也不为 true
 */
  private static final boolean TIMESTAMP_PRECISION_NANO =
      Boolean.getBoolean(TIMESTAMP_PRECISION_NANO_KEY);

  // Dump 得到 .pcap 文件的路径
  private static final String PCAP_FILE_KEY = Dump.class.getName() + ".pcapFile";
  private static final String PCAP_FILE = System.getProperty(PCAP_FILE_KEY, "Dump.pcap");

  private Dump() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    // 设置过滤器规则，为标准 BPF 规则表达式，如 args 为空则规则为 “”
    String filter = args.length != 0 ? args[0] : "";

    System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
    System.out.println(TIMESTAMP_PRECISION_NANO_KEY + ": " + TIMESTAMP_PRECISION_NANO);
    System.out.println("\n");

    // 声明包捕获网络接口对象
    PcapNetworkInterface nif;
    try {
      // 这一句是调用了已经封装好的命令行网卡选择函数，建议在开发自己的程序时不使用这个函数
      // 可以使用如下代码获取网卡列表
      /*
      import java.io.IOException;
      import org.pcap4j.core.PcapNetworkInterface;
      import org.pcap4j.core.PcapNativeException;
      import org.pcap4j.core.Pcaps;
      List allDevs = null;

        try {
            allDevs = Pcaps.findAllDevs();
        } catch (PcapNativeException var3) {
            throw new IOException(var3.getMessage());
        }

        if (allDevs != null && !allDevs.isEmpty()) {
            // do something here
            int deviceNum = 0;
            PcapNetworkInterface nif = Pcaps.getDevByName(alldev.get(deviceNum).getName());
        } else {
            throw new IOException("No NIF to capture.");
        }
       */
      nif = new NifSelector().selectNetworkInterface();
    } catch (IOException e) {
      e.printStackTrace();
      return;
    }

    if (nif == null) {
      return;
    }

    // 输出你选择了的网卡信息，其中 nifName 为 网卡标识，nifDescription 为 网卡显示名称
    System.out.println(nif.getName() + "(" + nif.getDescription() + ")");


    /*
     打开网卡，其中 PromiscuousMode 为网卡是否选择混杂模式（注：交换环境下混杂模式无效，只会侦听本广播网段的数据包）
     PcapHandle.Builder 是 PcapHandle 的子类, 初始化时需传入 nif.name, 调用 build() 函数可以得到一个 PcapHandle 对象实现对网卡的各种操作
     与 PcapHandle (只可以设置三个参数) 不同的是 Builder 类可以设置更多的参数 (调用相应的函数设置), 参数列表如下:
        private int snaplen; // 要捕获的最大数据包大小（以字节为单位）
        private PromiscuousMode promiscuousMode = null; // 网卡是否选择混杂模式, 为枚举类型（注：交换环境下混杂模式无效，只会侦听本广播网段的数据包）
        private boolean rfmon; // 网卡是否设置为监听模式, 如果系统不支持则使用默认
        private int timeoutMillis; // 等待读取数据包的时间（以毫秒为单位）, 必须非负 ,其中 0 代表一直等待直到抓到包为止
        private int bufferSize; // Dump 缓冲区大小设置
        private PcapHandle.TimestampPrecision timestampPrecision = null; // 时间戳精度, 为枚举类型, 分为毫秒和纳秒
        private PcapHandle.PcapDirection direction = null; // 设置抓包方向, 为枚举类型, 分为: 进出、进、出 三种方向
        private boolean immediateMode; // 立即模式, 该模式允许程序在数据包到达时立即处理它们

     */
    // 一个 Builder 对象就可以 build 多个 PcapHandle对象 (但是同属于一个网卡, 如需不同网卡则需多个 Builder 对象)
    // 这极大地方便了开发, 所以在程序设计中推荐这么做
    PcapHandle.Builder phb =
        new PcapHandle.Builder(nif.getName())
            .snaplen(SNAPLEN)
            .promiscuousMode(PromiscuousMode.PROMISCUOUS)
            .timeoutMillis(READ_TIMEOUT);
    if (TIMESTAMP_PRECISION_NANO) {
      phb.timestampPrecision(TimestampPrecision.NANO);
    }
    // PcapHandle 对象指的是对网卡的一系列操作，且 一个 PcapHandle 对象对应抓一个网卡的报文
    // 所以要捕获多网卡就要设置多个 PcapHandle，这就为同时进行多个抓包提供了可能
    PcapHandle handle = phb.build();

    // 设置网卡过滤器
    handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

    int num = 0;
    PcapDumper dumper = handle.dumpOpen(PCAP_FILE); // 用于 Dump .pcap 文件
    while (true) {
      PcapPacket packet = handle.getNextPacket(); // // 调用 getNextPacket 函数进行抓包, 一次得到一个包
      if (packet == null) {
        continue;
      } else {
        System.out.println(packet);
        dumper.dump(packet); // 依次将数据包 Dump 到文件中
        num++;
        if (num >= COUNT) {
          break;
        }
      }
    }

    // Dump 和抓包结束
    dumper.close();
    handle.close();
  }
}

```



#### 总结 #####

- 本文认识了 **Builder 类**及熟悉了 Builder 的**所有参数**，由于它的存在使我们的程序变得非常便捷
- 还知道了如何 dump 得到 .pcap 文件