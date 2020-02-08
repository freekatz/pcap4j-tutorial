package org.pcap4j.sample;

import java.io.IOException;
import java.net.Inet4Address;
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
import org.pcap4j.packet.*;
import org.pcap4j.packet.AbstractPacket.AbstractBuilder;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.IpV4Helper;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class SendFragmentedEcho {

  private static final String COUNT_KEY = SendFragmentedEcho.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 3);

  private static final String READ_TIMEOUT_KEY =
      SendFragmentedEcho.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = SendFragmentedEcho.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  // 发送 IP 数据包的大小, 也就是帧的传输单元大小
  private static final String TU_KEY = SendFragmentedEcho.class.getName() + ".tu";
  private static final int TU = Integer.getInteger(TU_KEY, 4000); // [bytes]

  // 最大传输单元, 也就是 IP 分片的最大大小
  private static final String MTU_KEY = SendFragmentedEcho.class.getName() + ".mtu";
  private static final int MTU = Integer.getInteger(MTU_KEY, 1403); // [bytes]

  private SendFragmentedEcho() {}

  public static void main(String[] args) throws PcapNativeException {
    String strSrcIpAddress = args[0]; // for InetAddress.getByName()
    String strSrcMacAddress = args[1]; // e.g. 12:34:56:ab:cd:ef
    String strDstIpAddress = args[2]; // for InetAddress.getByName()
    String strDstMacAddress = args[3]; // e.g. 12:34:56:ab:cd:ef

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

    // 此处与上一个代码的套路一样, 以下代码为初始化及回调函数定义
    PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    PcapHandle sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    ExecutorService pool = Executors.newSingleThreadExecutor();

    MacAddress srcMacAddr = MacAddress.getByName(strSrcMacAddress, ":");
    try {
      handle.setFilter(
          "icmp and ether dst " + Pcaps.toBpfString(srcMacAddr), BpfCompileMode.OPTIMIZE);

      PacketListener listener = packet -> System.out.println(packet);

      Task t = new Task(handle, listener);
      pool.execute(t);

      // 构造发送的 IP 数据包主体, -28 是减去了 20B 的 IP 头和 8B 的 MAC 头
      byte[] echoData = new byte[TU - 28];
      for (int i = 0; i < echoData.length; i++) {
        echoData[i] = (byte) i;
      }

      // 定义用于操作 ICMP 内层的 Builder, 包括标识符, 序号及选项
      // Echo 是 ICMP 的类型, 类型序号为 8, 所以需要注意**大多数**不同类型的 ICMP 内层数据需要不同的内层 Builder
      // 如 IcmpV4ParameterProblemPacket, IcmpV4TimestampPacket 等等, 一共 40 种
      // 构造 ICMP 内层
      IcmpV4EchoPacket.Builder echoBuilder = new IcmpV4EchoPacket.Builder();
      echoBuilder
          .identifier((short) 1) // ICMP 标识符
              // UnknownPacket 为未知的包对象, 适合用于 pcap4j 未定义的包协议, 但是这个不可以乱用, 在已知包协议的情况下最后不要用这个
              // 特别注意 UnknownPacket.Builder() 是一个静态的方法, 只能通过公共方法向其传递原始数据包, 方法包括设置 rawData 及 payload
          .payloadBuilder(new UnknownPacket.Builder().rawData(echoData));

      // 定义用于操作 ICMP 外层的 Builder, 包括类型, 代码, 校验和
      // 构造 ICMP 外层
      IcmpV4CommonPacket.Builder icmpV4CommonBuilder = new IcmpV4CommonPacket.Builder();
      icmpV4CommonBuilder
          .type(IcmpV4Type.ECHO) // ECHO 类型序号为 8,
          .code(IcmpV4Code.NO_CODE) // NO_CODE 代码序号为 0, 类型 8 + 代码 0 = ping 请求
          .payloadBuilder(echoBuilder)
          .correctChecksumAtBuild(true); // 校验和

      // 构造 IPV4
      IpV4Packet.Builder ipV4Builder = new IpV4Packet.Builder();
      try {
        ipV4Builder
            .version(IpVersion.IPV4)
            .tos(IpV4Rfc791Tos.newInstance((byte) 0))
            .ttl((byte) 100)
            .protocol(IpNumber.ICMPV4)
            .srcAddr((Inet4Address) InetAddress.getByName(strSrcIpAddress))
            .dstAddr((Inet4Address) InetAddress.getByName(strDstIpAddress))
            .payloadBuilder(icmpV4CommonBuilder)
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true);
      } catch (UnknownHostException e1) {
        throw new IllegalArgumentException(e1);
      }

      // // 构造以太帧
      EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
      etherBuilder
          .dstAddr(MacAddress.getByName(strDstMacAddress, ":"))
          .srcAddr(srcMacAddr)
          .type(EtherType.IPV4)
          .paddingAtBuild(true);

      for (int i = 0; i < COUNT; i++) {
        // 为 ICMP 和 IPV4 分别添加序号和标识, 此时还未分片
        echoBuilder.sequenceNumber((short) i);
        ipV4Builder.identification((short) i);

        // IpV4Helper.fragment 静态方法分片
        for (final Packet ipV4Packet : IpV4Helper.fragment(ipV4Builder.build(), MTU)) {
          /*
          这里介绍一下 AbstractBuilde, 顾名思义, 所有链路层以上特定协议的构造器都是继承自它
          由于, 此代码构造了 ping 请求的"新型 IPV4 数据包", 故最好将其归类为新的 AbstractPacket
          不过, 直接使用 IPV4 的构造器也是没问题的, 下面的代码也可以替换为它:
          etherBuilder.payloadBuilder(ipV4Packet.getBuilder());
           */
          etherBuilder.payloadBuilder(
              new AbstractBuilder() {
                @Override
                public Packet build() {
                  return ipV4Packet;
                }
              });

          Packet p = etherBuilder.build();
          sendHandle.sendPacket(p);

          try {
            Thread.sleep(100); // 发一个 IP 分片休息一下
          } catch (InterruptedException e) {
            break;
          }
        }

        try {
          Thread.sleep(1000); // 发一个完整的 IP 包休息一下
        } catch (InterruptedException e) {
          break;
        }
      }
    } catch (Exception e) {
      e.printStackTrace();
    } finally { // 结束释放资源
      if (handle != null && handle.isOpen()) {
        try {
          handle.breakLoop();
        } catch (NotOpenException noe) {
        }
        try {
          Thread.sleep(1000);
        } catch (InterruptedException e) {
        }
        handle.close();
      }
      if (sendHandle != null && sendHandle.isOpen()) {
        sendHandle.close();
      }
      if (pool != null && !pool.isShutdown()) {
        pool.shutdown();
      }
    }
  }

  private static class Task implements Runnable {

    private PcapHandle handle;
    private PacketListener listener;

    public Task(PcapHandle handle, PacketListener listener) {
      this.handle = handle;
      this.listener = listener;
    }

    @Override
    public void run() {
      try {
        handle.loop(-1, listener);
      } catch (PcapNativeException e) {
        e.printStackTrace();
      } catch (InterruptedException e) {
      } catch (NotOpenException e) {
        e.printStackTrace();
      }
    }
  }
}
