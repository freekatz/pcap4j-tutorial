介绍
======

从本文开始将对 **Pcap4J**（下文简称为 **p4**）提供的样例代码进行注释讲解，期间还包括了对 **Pcap 原理**的解读

****

每篇文章讲解一个样例，目录如下：
目录
-----
- [ReadPacketFile](#ReadPacketFile)
  - [原理](#原理)
  - [步骤](#步骤)
  - [实现](#实现)
  - [总结](#总结)

****

ReadPacketFile
------

#### 原理 #####

没有什么好介绍的原理，之前都说过了

#### 步骤 #####

略

#### 实现 #####

```java
package org.pcap4j.sample;

import java.io.EOFException;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

@SuppressWarnings("javadoc")
public class ReadPacketFile {

  private static final int COUNT = 5;

  private static final String PCAP_FILE_KEY = ReadPacketFile.class.getName() + ".pcapFile";
  private static final String PCAP_FILE =
      System.getProperty(PCAP_FILE_KEY, "src/main/resources/echoAndEchoReply.pcap");

  private ReadPacketFile() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    PcapHandle handle;
    try {
      // 时间戳精度为纳秒
      handle = Pcaps.openOffline(PCAP_FILE, TimestampPrecision.NANO);
    } catch (PcapNativeException e) {
      handle = Pcaps.openOffline(PCAP_FILE);
    }

    for (int i = 0; i < COUNT; i++) {
      try {
        Packet packet = handle.getNextPacketEx();
        System.out.println(packet);
      } catch (TimeoutException e) {
      } catch (EOFException e) {
        System.out.println("EOF");
        break;
      }
    }

    handle.close();
  }
}
```

#### 总结 #####

GetNextPacketEx 读取离线 pcap 文件