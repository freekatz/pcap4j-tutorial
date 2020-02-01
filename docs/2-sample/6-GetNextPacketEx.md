介绍
======

从本文开始将对 **Pcap4J**（下文简称为 **p4**）提供的样例代码进行注释讲解，期间还包括了对 **Pcap 原理**的解读

****

GetNextPacketEx
------

#### 原理 #####

这里介绍一下理解本篇文章的关键函数：**dispatch 函数**

- dispatch 函数有两种重载形式，参数与 **loop** 函数一样
- dispatch 和 loop 非常像，但是有本质上的不同：
  - dispatch 根据**超时时间**是否达到来决定是否返回，而 loop 则根据**抓包数目**是否达到来返回
  -  loop 由**数据包捕获驱动**直接调用，用户无法直接控制 loop（意思就是 loop 函数太局限了）正因为如此使得 dispatch **适合应用于复杂程序**
- dispatch 是 **getNextPacket** 函数的基础，相当于 **packetCount = 1** 的 dispatch 函数，所以 getNextPacket 函数的**效率比较低**（因为它要等待超时）

综上，出现了一种更好的选择：**GetNextPacketEx** 函数，**无需回调的抓包方法**，这是因为

- 回调的方法有时候并不实用，看似精妙，但是即增加了程序的复杂度还影响程序的可读性，也就是**花里胡哨**的意思
- dispatch 和 loop 都是回调的方式，所以我们不选择
- getNextPacket 基于 dispatch，**只是隐藏了回调**，而且效率低下
- 最关键的是，相比于 getNextPacket ，Ex 版本增加了**更多的异常处理**，而这些异常是经常发生的

#### 步骤 #####

- 初始化，打开、读取网卡，设置过滤器规则
- 处理、编译过滤规则
- 捕获数据包，及进行其他操作
- 捕获完毕，关闭网卡

#### 实现 #####

```java
package org.pcap4j.sample;

import java.io.EOFException;
import java.io.IOException;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class GetNextPacketEx {

  private static final String COUNT_KEY = GetNextPacketEx.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 5);

  private static final String READ_TIMEOUT_KEY = GetNextPacketEx.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = GetNextPacketEx.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  private GetNextPacketEx() {}

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

    try (PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT)) {
      handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

      int num = 0;
      while (true) {
        try {
          // 此代码的重点在这里:
          /*
          Ex 顾名思义, 即扩展版, 扩展在哪里呢?
          1. Ex 版本可以捕获更多的异常, 而且这些异常是经常出现的, 比如: 超时, 出错, EOF, 在不同情况下，Ex 版本会返回不同的值, 当然这些我们不必担心
             而非 Ex 版本只可以捕获网卡打开失败的异常, 这在应用场景下是不可靠的
          2. 非 Ex 版本的效率低下，尽管它也隐藏了回调的方式，但依然依赖于函数 dispatch (参数 packetCount 为 1)
          3. 非 Ex 版本不能检测到文件末尾这个状态(EOF)，因此，如果数据包是从文件读取来的，必须使用 Ex 版本 (见 ReadPacket 样例)。
           */
          Packet packet = handle.getNextPacketEx();
          System.out.println(packet);
          num++;
          if (num >= COUNT) {
            break;
          }
        } catch (TimeoutException e) {
        } catch (EOFException e) {
          e.printStackTrace();
        }
      }
    }
  }
}

```



#### 总结 #####

自此，我们以及认识了所有捕获数据包的方法，其中最优的是 **GetNextPacketEx**