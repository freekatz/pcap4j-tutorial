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
