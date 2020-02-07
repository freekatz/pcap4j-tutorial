介绍
======

从本文开始将对 **Pcap4J**（下文简称为 **p4**）提供的样例代码进行注释讲解，期间还包括了对 **Pcap 原理**的解读

****

每篇文章讲解一个样例，目录如下：
目录
-----
- [SendArpRequest](#SendArpRequest)
  - [原理](#原理)
  - [步骤](#步骤)
  - [实现](#实现)
  - [总结](#总结)

****

SendArpRequest
------

#### 原理 #####

此样例代码示范如何发送 ARP 请求

在代码之前，本文将对 ARP 协议规范、ARP 欺骗原理及中间人攻击（MITM）做必要的介绍，也是为了项目做准备

**ARP 协议**

**ARP 欺骗**

**MITM**

#### 步骤 #####

- 初始化 ARP 请求的参数，初始化网卡
- 构造 ARP 数据包及以太网帧
- 发送 ARP 请求并捕获 ARP响应
- 完成释放资源

#### 实现 #####

```java
package org.pcap4j.sample;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class SendArpRequest {

  private static final String COUNT_KEY = SendArpRequest.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 1);

  private static final String READ_TIMEOUT_KEY = SendArpRequest.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = SendArpRequest.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  // 发送 ARP 请求的源 MAC地址, 需填写正确, 否则接收不到 ARP 响应, 格式为: "-" 或 ":" 分隔开
  // D0-C6-37-3E-7A-fB, d0-c6-37-3e-7a-fb, d0:c6:37:3e:7a:fb 均可, 不区分大小写
  private static final MacAddress SRC_MAC_ADDR = MacAddress.getByName("d0:c6:37:3e:7a:fb");

  // 响应的 MAC 地址
  private static MacAddress resolvedAddr;

  private SendArpRequest() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    // 源 IP 地址, 需填写正确
    String strSrcIpAddress = "192.168.1.121"; // for InetAddress.getByName()
    // 目的 IP 地址, 需填写正确
    String strDstIpAddress = args[0]; // for InetAddress.getByName()

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

    // 为什么需要使用两个 Handle 呢? 之前说过同一个 Handle 只可以操作一张网卡, 现在做一下补充
    // 由于此程序既要发包, 还要抓这个自己发的包, 所以需要单独使用一个 Handle
    // 不过就算不是这样, 也推荐, 发包和抓包尽量不要使用同一个 Handle
    PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    PcapHandle sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

    // 定义了一个不可重用的单一的线程池, 专门用来捕获 ARP 数据包, 此线程池是一个无界的线程队列(队列大小无限制)
    // 且线程池中同时只会有一个线程运行
    // 关于那几种线程池等到开始做项目用到时再来探究
    ExecutorService pool = Executors.newSingleThreadExecutor();

    try {
      // 设置用于捕获 ARP 响应的 BPF 过滤器规则
      handle.setFilter(
          "arp and src host "
              + strDstIpAddress
              + " and dst host "
              + strSrcIpAddress
              + " and ether dst "
              + Pcaps.toBpfString(SRC_MAC_ADDR),
          BpfCompileMode.OPTIMIZE);

      // listener 的回调函数, 逻辑很简单
      // 先判断是否是 ARP 包, 再判断是不是 ARP 响应, 如果是则将 ARP 响应体包括的 MAC 作为响应得到的 MAC
      PacketListener listener =
          packet -> {
            if (packet.contains(ArpPacket.class)) {
              ArpPacket arp = packet.get(ArpPacket.class);
              if (arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
                SendArpRequest.resolvedAddr = arp.getHeader().getSrcHardwareAddr();
              }
            }
            // 输出响应包
            System.out.println(packet);
          };

      // Task 为继承自 Runnable 的任务线程, 用于捕获 ARP 响应
      Task t = new Task(handle, listener);
      // 将 Task 放入线程池并运行线程池
      pool.execute(t);

      // 以下是构造 ARP 数据包的过程
      // 初始化一个 ArpBuilder 对象用于操作 ARP 数据包
      ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
      try {
        // 添加参数
        arpBuilder
            .hardwareType(ArpHardwareType.ETHERNET) // 硬件类型为以太网, 如果电脑连接的是 WiFi 热点, 也可改为 IEEE.802, 总之必须对应上
            .protocolType(EtherType.IPV4) // 协议类型为 IPV4
            .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES) // MAC 长度
            .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES) // IP 长度
            .operation(ArpOperation.REQUEST) // ARP 类型为: 请求
            .srcHardwareAddr(SRC_MAC_ADDR) // 源 MAC
            .srcProtocolAddr(InetAddress.getByName(strSrcIpAddress)) // 源 IP
             // 目的MAC: 广播地址, 也可改为 MacAddress.getByName("ff-ff-ff-ff-ff-ff")
            .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
             // 目的 IP
            .dstProtocolAddr(InetAddress.getByName(strDstIpAddress));
      } catch (UnknownHostException e) {
        throw new IllegalArgumentException(e); // 参数错误异常
      }

      // 以下是构造以太网帧的过程
      // 初始化一个 etherBuilder 对象用于操作帧
      EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
      etherBuilder
          .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
          .srcAddr(SRC_MAC_ADDR)
          .type(EtherType.ARP) // 帧类型
          .payloadBuilder(arpBuilder) // 由于 ARP 请求是包含在帧里的, 故需要做一个 payload
          .paddingAtBuild(true); // 是否填充至以太网的最小帧长, 必须为 true, 否则对方不会接受请求

      // 发送 count 个请求, 请注意如果将 count 改为无限, 每隔一定时间向目的战点发送特定的 ARP 请求, 即可达到 ARP 欺骗的作用
      for (int i = 0; i < COUNT; i++) {
        Packet p = etherBuilder.build();
        System.out.println(p);
        sendHandle.sendPacket(p);
        try {
          Thread.sleep(1000);
        } catch (InterruptedException e) {
          break;
        }
      }// 最后, 回收资源
    } finally {
      if (handle != null && handle.isOpen()) {
        handle.close();
      }
      if (sendHandle != null && sendHandle.isOpen()) {
        sendHandle.close();
      }
      if (pool != null && !pool.isShutdown()) {
        pool.shutdown();
      }

      System.out.println(strDstIpAddress + " was resolved to " + resolvedAddr);
    }
  }

  // 下面是 Task 子类的定义, 重载了 Runnable 的默认回调函数 run
  private static class Task implements Runnable {

    private PcapHandle handle;
    private PacketListener listener;

    public Task(PcapHandle handle, PacketListener listener) {
      this.handle = handle;
      this.listener = listener;
    }

    @Override // 将 run 重载为使用 loop 方法捕获数据包
    public void run() {
      try {
        handle.loop(COUNT, listener);
      } catch (PcapNativeException e) {
        e.printStackTrace();
      } catch (InterruptedException e) {
        e.printStackTrace();
      } catch (NotOpenException e) {
        e.printStackTrace();
      }
    }
  }
}

```



#### 总结 #####

本文详细介绍了 ARP 相关的原理，并进一步说明了 ARP 欺骗、MITM 及两者之间的关系

在此基础上详细地注释了样例代码，此时读者应该可以自己编写 ARP 欺骗等等进阶程序了