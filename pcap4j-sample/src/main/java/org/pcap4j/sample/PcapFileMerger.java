package org.pcap4j.sample;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.core.Pcaps;

@SuppressWarnings("javadoc")
public class PcapFileMerger {

  private PcapFileMerger() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    // args: pcap file list

    PcapDumper dumper = null;
    for (String pcapFile : args) {
      PcapHandle handle = Pcaps.openOffline(pcapFile);

      if (dumper == null) {
        // handle.dumpOpen 返回一个 dumper 对象
        dumper = handle.dumpOpen(PcapFileMerger.class.getSimpleName() + ".pcap");
      }

      // dump packet, 注意, 这里使用的是 handle.getNextPacket() 还不是 Ex 版本
      PcapPacket packet;
      while ((packet = handle.getNextPacket()) != null) {
        dumper.dump(packet);
      }

      handle.close();
    }

    if (dumper != null) {
      dumper.close();
    }
  }
}
