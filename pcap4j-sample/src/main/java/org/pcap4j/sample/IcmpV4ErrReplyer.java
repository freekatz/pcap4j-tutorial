package org.pcap4j.sample;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.pcap4j.core.*;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4DestinationUnreachablePacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IcmpV4ParameterProblemPacket;
import org.pcap4j.packet.IcmpV4TimeExceededPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.IcmpV4Helper;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class IcmpV4ErrReplyer {

  private static MacAddress MAC_ADDR = MacAddress.getByName("ec:26:ca:7e:d8:aa"); // 可设为网关 MAC

  private IcmpV4ErrReplyer() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    // strAddress 为域名或主机名, 可直接设为本机 ip
    String strAddress = args[0];
    // ICMP 类型和代码都位于 ICMP 外层, 可唯一标识一种 ICMP 内层结构
    String strType =
        args[1]; // 3(DESTINATION_UNREACHABLE) or 11(TIME_EXCEEDED) or 12(PARAMETER_PROBLEM)
    String strCode = args[2];

    // 初始化 IP
    final Inet4Address address;
    try {
      // 注意一下这里, address 指的是域名或者主机名, 而 hostAddress 才是 IPv4地址
      // InetAddress 是 IP 地址对象, 分为 v4 和 v6, 且提供了得到 IP 地址的几种方法, 不详细介绍, 查看注释理解起来很简单
      address = (Inet4Address) InetAddress.getByName(strAddress);
    } catch (UnknownHostException e1) {
      throw new IllegalArgumentException("args[0]: " + strAddress);
    }

    // 初始化类型的实例或句柄
    final IcmpV4Type type;
    try {
      type = IcmpV4Type.getInstance(Byte.parseByte(strType));
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("args[1]: " + strType, e);
    }
    if (!type.equals(IcmpV4Type.DESTINATION_UNREACHABLE)
        && !type.equals(IcmpV4Type.TIME_EXCEEDED)
        && !type.equals(IcmpV4Type.PARAMETER_PROBLEM)) {
      throw new IllegalArgumentException("args[1]: " + strType);
    }

    // 初始化 code
    IcmpV4Code code;
    try {
      code = IcmpV4Code.getInstance(type.value(), Byte.parseByte(strCode));
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("args[1]: " + strType, e);
    }

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

    final PcapHandle handle4capture = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);

    final PcapHandle handle4send = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);

    handle4capture.setFilter( // 只监听发往网关的数据包
        "(ether dst "
            + MAC_ADDR
            + ") or (arp and ether dst "
            + Pcaps.toBpfString(MacAddress.ETHER_BROADCAST_ADDRESS)
            + ")",
        BpfCompileMode.OPTIMIZE);

    // 根据不同的 type 生成不同的 Builder, 用于控制 icmp 的内层
    Packet.Builder tmp;
    if (type.equals(IcmpV4Type.DESTINATION_UNREACHABLE)) {
      tmp = new IcmpV4DestinationUnreachablePacket.Builder();
    } else if (type.equals(IcmpV4Type.TIME_EXCEEDED)) {
      tmp = new IcmpV4TimeExceededPacket.Builder();
    } else if (type.equals(IcmpV4Type.PARAMETER_PROBLEM)) {
      tmp = new IcmpV4ParameterProblemPacket.Builder();
    } else {
      throw new AssertionError();
    }

    // 使用 tmp 的原因是 icmpv4errb(有很多类型) 想要定义成 final, 则必须使用临时变量(确定了类型)复制给它
    final Packet.Builder icmpV4errb = tmp;

    // 生成 icmp 外层的 Builder, 然后传入内层的 Builder
    IcmpV4CommonPacket.Builder icmpV4b = new IcmpV4CommonPacket.Builder();
    icmpV4b.type(type).code(code).payloadBuilder(icmpV4errb).correctChecksumAtBuild(true);

    // 与上面同理, 生成 ipv4 的 Builder, 然后传入 icmp 的 Builder
    final IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
    ipv4b
        .version(IpVersion.IPV4)
        .tos(IpV4Rfc791Tos.newInstance((byte) 0)) // Type of service, 区分服务
        .identification((short) 100) // 标识符
        .ttl((byte) 100) // time to live, 存活时间
        .protocol(IpNumber.ICMPV4) // 协议
        .payloadBuilder(icmpV4b)
        .correctChecksumAtBuild(true) // 计算校验和
        .correctLengthAtBuild(true); // 计算长度

    // 与上面同理, 生成 Ethernet 的 Builder, 然后传入 IP 的 Builder
    final EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.type(EtherType.IPV4).payloadBuilder(ipv4b).paddingAtBuild(true); // 填充

    // 上面的过程只是简单的确定了数据包的结构, 数据包的内部详细还没有确定

    // 收到目标机器的任意数据包(非 icmp error)则向其回复 icmp error
    // 这里需要注意, 以下代码不会拦截数据包, 所以正常情况下, 数据包也会到达真正的目的地, 本机也会收到来自真正目的地的回复
    // 本程序只是仿真这个过程而已
    final PacketListener listener =
        packet -> { // 回调逻辑 -> 确定数据包内部详细 -> 回复 icmp
        // 如果收到的报文为 icmp 回送请求或回送回答报文
          if (packet.contains(IcmpV4EchoPacket.class)) {
            if (type.equals(IcmpV4Type.DESTINATION_UNREACHABLE)) {
              ((IcmpV4DestinationUnreachablePacket.Builder) icmpV4errb)
                  .payload(
                      IcmpV4Helper.makePacketForInvokingPacketField(packet.get(IpV4Packet.class)));
            } else if (type.equals(IcmpV4Type.TIME_EXCEEDED)) {
              ((IcmpV4TimeExceededPacket.Builder) icmpV4errb)
                  .payload(
                      IcmpV4Helper.makePacketForInvokingPacketField(packet.get(IpV4Packet.class)));
            } else if (type.equals(IcmpV4Type.PARAMETER_PROBLEM)) {
              ((IcmpV4ParameterProblemPacket.Builder) icmpV4errb)
                  .payload(
                      IcmpV4Helper.makePacketForInvokingPacketField(packet.get(IpV4Packet.class)));
            }

            // 确定地址
            ipv4b.srcAddr(packet.get(IpV4Packet.class).getHeader().getDstAddr());
            ipv4b.dstAddr(packet.get(IpV4Packet.class).getHeader().getSrcAddr());
            eb.srcAddr(packet.get(EthernetPacket.class).getHeader().getDstAddr());
            eb.dstAddr(packet.get(EthernetPacket.class).getHeader().getSrcAddr());

            // 发送
            try {
              handle4send.sendPacket(eb.build());
              System.out.println(eb.build());
            } catch (PcapNativeException e) {
              e.printStackTrace();
            } catch (NotOpenException e) {
              e.printStackTrace();
            }
            // 如果收到的报文为 arp
          } else if (packet.contains(ArpPacket.class)) {
            ArpPacket ap = packet.get(ArpPacket.class);
            // 判断 arp 是不是发给本机的
            if (!ap.getHeader().getOperation().equals(ArpOperation.REQUEST)) {
              return; // 如果不是 arp 请求则直接返回, arp 不是发给本机的
            }
            if (!ap.getHeader().getDstProtocolAddr().equals(address)) {
              return; // 如果收到的 arp 目的地址不是本机, 则直接返回, arp 不是发给本机的
            }
            // arp 是发给本机的, 以下过程为构造 arp 响应
            EthernetPacket.Builder eb1 = packet.getBuilder().get(EthernetPacket.Builder.class);
            ArpPacket.Builder ab = eb1.get(ArpPacket.Builder.class);

            ab.srcHardwareAddr(MAC_ADDR)
                .dstHardwareAddr(ap.getHeader().getSrcHardwareAddr())
                .srcProtocolAddr(ap.getHeader().getDstProtocolAddr())
                .dstProtocolAddr(ap.getHeader().getSrcProtocolAddr())
                .operation(ArpOperation.REPLY);

            eb1.dstAddr(ap.getHeader().getSrcHardwareAddr()).srcAddr(MAC_ADDR);

            try {
              handle4send.sendPacket(eb1.build());
            } catch (PcapNativeException e) {
              e.printStackTrace();
            } catch (NotOpenException e) {
              e.printStackTrace();
            }
          } // 注意这里没有进一步写其它情况, 我们可以加其他情况
//          else{
//            System.out.println(packet);
//          }
        };

    ExecutorService executor = Executors.newSingleThreadExecutor();
    executor.execute(
        new Runnable() {
          @Override
          public void run() {
            while (true) {
              try {
                handle4capture.loop(-1, listener);
              } catch (PcapNativeException e) {
                e.printStackTrace();
              } catch (InterruptedException e) {
                break;
              } catch (NotOpenException e) {
                break;
              }
            }
          }
        });

    block(); // 输入回车关闭程序
    handle4capture.breakLoop();

    handle4capture.close();
    handle4send.close();
    executor.shutdown();
  }

  private static void block() {
    try {
      Thread.sleep(2000);
    } catch (InterruptedException e1) {
    }

    BufferedReader r = null;

    try { // 读入命令行输入, 即输入回车结束程序
      r = new BufferedReader(new InputStreamReader(System.in));
      System.out.println("** Hit Enter key to stop simulation **");
      r.readLine();
    } catch (IOException e) {
      e.printStackTrace();
    } finally {
      try {
        if (r != null) {
          r.close();
        }
      } catch (IOException e) {
      }
    }
  }
}
