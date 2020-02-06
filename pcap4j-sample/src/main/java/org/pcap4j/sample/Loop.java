package org.pcap4j.sample;

import com.sun.jna.Platform;
import java.io.IOException;

import org.pcap4j.core.*;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class Loop {

  // 设置 COUNT 常量，代表本次捕获数据包的数目，其中 -1 代表一直捕获
  private static final String COUNT_KEY = Loop.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, -1);

  // 等待读取数据包的时间（以毫秒为单位）, 必须非负 ,其中 0 代表一直等待直到抓到包为止
  private static final String READ_TIMEOUT_KEY = Loop.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 0); // [ms]

  // 要捕获的最大数据包大小（以字节为单位）
  private static final String SNAPLEN_KEY = Loop.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  private Loop() {}

  // 主函数
  public static void main(String[] args) throws PcapNativeException, NotOpenException {

    // 设置过滤器规则，为标准 BPF 规则表达式，如 args 为空则规则为 “”
    String filter = args.length != 0 ? args[0] : "";

    System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
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

    // 打开网卡，其中 PromiscuousMode 为网卡是否选择混杂模式（注：交换环境下混杂模式无效，只会侦听本广播网段的数据包）
    // 其中 PcapHandle 对象指的是对网卡的一系列操作，且 一个 PcapHandle 对象对应抓一个网卡的报文
    // 所以要捕获多网卡就要设置多个 PcapHandle，这就为同时进行多个抓包提供了可能
    final PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    // 设置网卡过滤器
    if (filter.length() != 0) {
      handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
    }

    // 开始侦听，其中 PacketListener 实现了一个接口
    // 其中的 -> 代表的是 Java 的 Lambda 表达式, 解释如下:
    /*
      listener 会将侦听得到的 packet 作为回调参数 var1 传入 PacketListener 回调函数 void gotPacket(PcapPacket var1); 中
      所以 packet -> System.out.println(packet); 相当于实现了 PacketListener 接口, 其中实现的回调函数为将传入的 packet 直接输出
     */
    PacketListener listener = packet -> System.out.println(packet);
    // 进一步的说, 以上代码就相当于下面的代码
    /*
    抓到报文回调gotPacket方法处理报文内容
    PacketListener listener =
            new PacketListener() {
              @Override
              public void gotPacket(PcapPacket packet) {
                // 抓到报文走这里...
                System.out.println(packet);
              }
            };
    */

    // 调用 loop 函数（还有许多其他捕获数据包的方法，日后再说）进行抓包，其中抓到的包则回调 listener 指向的回调函数
    try {
      handle.loop(COUNT, listener);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }

    // PcapStat 对象为本次抓包的统计信息
    PcapStat ps = handle.getStats();
    System.out.println("ps_recv: " + ps.getNumPacketsReceived());
    System.out.println("ps_drop: " + ps.getNumPacketsDropped());
    System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
    if (Platform.isWindows()) {
      System.out.println("bs_capt: " + ps.getNumPacketsCaptured());
    }

    // 关闭网卡
    handle.close();
  }
}
