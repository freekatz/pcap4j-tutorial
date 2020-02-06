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
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.HttpStatusCode;
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
