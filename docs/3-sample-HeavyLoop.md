介绍
======

从本文开始将对 **Pcap4J**（下文简称为 **p4**）提供的样例代码进行注释讲解，期间还包括了对 **Pcap 原理**的解读

****

每篇文章讲解一个样例，目录如下：
目录
-----
- [Loop](./2-sample-Loop.md)
- [HeavyLoop（本篇文章）](#HeavyLoop)
  - [原理](#原理)
  - [步骤](#步骤)
  - [实现](#实现)
  - [总结](#总结)
- [Dump](./4-sample-Dump.md)
- [DumpLoop](./5-sample-DumpLoop.md)
- [GetNextPacket](./6-sample-GetNextPacket.md)
- [GetNextPacketEx](./7-sample-GetNextPacketEx.md)
- [DefragmentEcho](./8-sample-DefragmentEcho.md)
- [IcmpV4ErrReplyer](./9-sample-IcmpV4ErrReplyer.md)
- [SendArpRequest](./10-sample-SendArpRequest.md)
- [SendFragmentedEcho](./11-sample-SendFragmentedEcho.md)
- [PacketStream](./12-sample-PacketStream.md)
- [PcapFileMerger](./13-sample-PcapFileMerger.md)
- [ReadPacketFile](./14-sample-ReadPacketFile.md)
- [Docket](./15-sample-Docket.md)

****

HeavyLoop
------

#### 原理 #####

HeavyLoop 在 Loop 的基础上加入了工业级的线程池，适用于大型的短期异步任务，当在繁忙的网络中抓包或者在大型网络中进行嗅探时可以极大地提高程序性能。

#### 步骤 #####

- 初始化，打开、读取网卡，设置过滤器规则（本程序略过了过滤器设置），及设置网卡模式
- 处理、编译过滤规则（略）
- 捕获数据包（使用线程池），及进行其他操作（可自己设置回调函数）
- 捕获完毕，关闭网卡

#### 实现 #####

```java
package org.pcap4j.sample;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class HeavyLoop {

  private HeavyLoop() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
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

    // 打开网卡，其中
    /*
    65536 为要捕获的最大数据包大小（以字节为单位）
    PromiscuousMode 为网卡是否选择混杂模式（注：交换环境下混杂模式无效，只会侦听本广播网段的数据包）
    10 为等待读取数据包的时间（以毫秒为单位），其中 -1 代表一直等待
     */
    // 其中 PcapHandle 对象指的是对网卡的一系列操作，且 一个 PcapHandle 对象对应抓一个网卡的报文
    // 所以要捕获多网卡就要设置多个 PcapHandle，这就为同时进行多个抓包提供了可能
    final PcapHandle handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);


    // 开始侦听，其中 PacketListener 实现了一个接口
    // 其中的 -> 代表的是 Java 的 Lambda 表达式, 解释如下:
    /*
      listener 会将侦听得到的 packet 作为回调参数 var1 传入 PacketListener 回调函数 void gotPacket(PcapPacket var1); 中
      所以 packet -> System.out.println(packet); 相当于实现了 PacketListener 接口, 其中实现的回调函数为 {} 中的代码
     */
    PacketListener listener =
        packet -> {
          System.out.println("start a heavy task");
          try {
            Thread.sleep(5000);
          } catch (InterruptedException e) {

          }
          System.out.println("done");
        };

    // 下面的代码是这次的重点
    /*
    1. Executor, ExecutorService, Executors 同属于 Executor 框架, 提供了启动, 管理和调度线程/线程池的接口和操作
    2. 其中 ExecutorService 接口继承自 Executor 接口，它提供了更丰富的实现多线程的方法, 比如其中包括了使用 shutdown 方法来平滑地广播线程池
    3. Executors 类提供了一系列工厂方法用于创建线程池, 如:
    public static ExecutorService newFixedThreadPool(int nThreads) // 创建固定数目线程的线程池。
    public static ExecutorService newCachedThreadPool() //创建一个可缓存的线程池
    等
     */
    /* newCachedThreadPool() 创建了一个可缓存线程池，
    如果线程池长度超过处理需要，可灵活回收空闲线程，
    若无可回收，则新建线程，但是在以前构造的线程可用时将重用它们。
    对于执行很多短期异步任务的程序而言，这些线程池通常可提高程序性能。
    */
    try {
      ExecutorService pool = Executors.newCachedThreadPool();
      // 我们只需向 loop 函数传入 pool 即可, p4 作者已经将线程池的实现封装好
      handle.loop(5, listener, pool); // This is better than handle.loop(5, listener);
      /*
      调用 shutdown 方法后，将导致ExecutorService停止接受任何新的任务且等待已经提交的任务执行完成
      (已经提交的任务会分两类：一类是已经在执行的，另一类是还没有开始执行的)，当所有已经提交的任务执行完毕后将会关闭ExecutorService
      因此我们一般用该接口来实现和管理多线程。
       */
      pool.shutdown();
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    // 关闭网卡
    handle.close();
  }
}

```

#### 总结 #####

**只需记住捕获数据包的函数可传入线程池即可，强烈推荐这么做**