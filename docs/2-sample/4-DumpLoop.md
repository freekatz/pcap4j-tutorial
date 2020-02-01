介绍
======

从本文开始将对 **Pcap4J**（下文简称为 **p4**）提供的样例代码进行注释讲解，期间还包括了对 **Pcap 原理**的解读

****

每篇文章讲解一个样例，目录如下：
目录
-----
- [DumpLoop](#DumpLoop)
  - [原理](#原理)
  - [步骤](#步骤)
  - [实现](#实现)
  - [总结](#总结)

****

DumpLoop
------

#### 原理 #####

[注意]从这篇文章开始，已经讲解过的不再重复

此代码的原理就是 Loop 和 Dump 的简易结合体，无需啰嗦

#### 步骤 #####

- 初始化、定义 handle
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
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class DumpLoop {

  private static final String COUNT_KEY = DumpLoop.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 5);

  private static final String READ_TIMEOUT_KEY = DumpLoop.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = DumpLoop.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  private static final String PCAP_FILE_KEY = DumpLoop.class.getName() + ".pcapFile";
  private static final String PCAP_FILE = System.getProperty(PCAP_FILE_KEY, "DumpLoop.pcap");

  private DumpLoop() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    String filter = args.length != 0 ? args[0] : "";

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

    final PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

    handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

    PcapDumper dumper = handle.dumpOpen(PCAP_FILE);
    try {
      /*
      此代码只需注意这里，这里的 loop() 是重载函数，它封装了 jna 中 pcap_loop 的重载
      到目前为止，loop 函数的两种实现我们全认识了
      在这里，loop 函数直接将捕获的数据包 dump
       */
      handle.loop(COUNT, dumper);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }

    dumper.close();
    handle.close();
  }
}

```

#### 总结 #####

如果我们的程序的主要目的就是 dump 而无需对数据包进行处理时，DumpLoop 的方法更加适合