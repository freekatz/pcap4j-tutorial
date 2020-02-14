介绍
======

从本文开始将对 **Pcap4J**（下文简称为 **p4**）提供的样例代码进行注释讲解，期间还包括了对 **Pcap 原理**的解读

****

每篇文章讲解一个样例，目录如下：
目录
-----
- [PcapFileMerger](#PcapFileMerger)
  - [原理](#原理)
  - [步骤](#步骤)
  - [实现](#实现)
  - [总结](#总结)

****

PcapFileMerger
------

#### 原理 #####

通过本文了解使用 **p4** 的 dumper 对象操作 .pcap 文件

#### 步骤 #####

略

#### 实现 #####

```java
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
```

#### 总结 #####

学习了 pcap 文件合并的原理和步骤