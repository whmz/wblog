---
title: 一个流量标记问题导致的限速Bug
date: 2018-03-10 21:05:06
tags: 
---

继续之前限速脚本的话题，本次整理下处理的一个限速Bug。

近期对网络出口做了扩容，按监控的带宽数据来算，目前有20%左右的裕量，按说用户那边不再那么卡了，但是这周总是接到用户投诉说网速达不到，并发了相应的截图。为了排查具体的情况，在周三、四做了两次的问题排查，终于发现了问题点。本文简单记录下问题发现和排查过程。

## 问题时间点
我们运营的学校在这周开学，大概从周二开始，有用户投诉带宽问题。考虑带宽和限速模块没有做过调整，本来是很确信不会有问题，毕竟已经正常运行了那么久的系统了！但是周三，我们自己的客服也在反馈这个问题，并拿到了实际测试的结果：在各种带宽的测试环境下，基本达不到预期的值，特别是在50M环境下，一般还达不到20M。这样基本说明，问题点确实存在，需要详细排查下。

## 第一次检查
周三因为要解决另外的问题，在观察问题流量的同时，对系统做了次简单的检查。大致的流程如下：
1. 检查用户拨号后，下发的限速值是否正确
    这个可以通过syslog日志输出的限速参数检查，发现测速有问题的账号，实际限速参数并没有问题，上行20M，下行50M。在检查后再次测速，速率仍有较大差异。

2. 检查限速参数是否正确应用到了tc的正确队列
    按上篇文章的介绍，用户IP和tc队列有个确定的对应关系，tc_class = (srcIP & 0xff) + 1, 根据这个计算出用户队列，检查对应的上下行参数，正确。
    ```
     |     
     +---(10:1daf) htb prio 1 rate 20Mbit ceil 20Mbit burst 1600b cburst 1600b 
     |             Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0) 
     |             rate 0bit 0pps backlog 0b 0p requeues 0 
    --
     |             rate 0bit 0pps backlog 0b 0p requeues 0 
     |     
     +---(10:1daf) htb prio 1 rate 50Mbit ceil 50Mbit burst 1600b cburst 1600b 
     |             Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0) 
     |             rate 0bit 0pps backlog 0b 0p requeues 0
    ```

3. 经过这两步检查，发现用户速率没有问题，这时候怀疑是不是上行带宽实际上没有扩容？
    使用了[speettest的脚本](https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py) 检查服务器带宽：
    ```
    wget https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py
    python speedtest.py 
    ```
    检查发现，在当时负载比较高、接近扩容前带宽的情况下，速率仍能达到1957Mbps，可以判断出口带宽已经扩容了。

4. 这样，排除外部原因，开始检查下校园网络的情况。因为接入方式流量跑在校园网上，如果校园网情况不好，带宽也起不来。
    安排了客服下载校园内服务器的资源，可以跑满100M....

经过这几步排查，发现问题确实存在，但排除了下发错误、限速参数设置、出口带宽、内部网络故障这几个原因，有可能是服务程序问题。这时候也有客服反馈，现场有单个账号出问题的，只有某个账号速率不足，50M只能到10Mbps，同样环境换账号就可以。这样差不多可以怀疑限速功能是有问题了。

之后是校园停电，12点了，没有办法继续试验排查，再加上有其他问题检查解决，也就暂时放下了这个问题。

## 第二次检查
周四，在解决了其他问题后，重新开始检查限速的问题。这时候，因为排除了一些因素，重点放到了限速的功能上，但是还没相信是代码问题....大致做了这么些检查：
1. 确定一个账号先检查
    在这个用户登录后，获取其登录IP地址，10.151.25.99, 换算其tc-class为 10:1965, 检查其tc限速参数
    ```
    []@vser:~$ sudo /etc/xlipsec/mark_tc.sh status ens3f0 ens3f1| grep -C 2 10:1965
     |             rate 0bit 0pps backlog 0b 0p requeues 0 
     |     
     +---(10:1965) htb prio 1 rate 20Mbit ceil 20Mbit burst 1600b cburst 1600b 
     |             Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0) 
     |             rate 0bit 0pps backlog 0b 0p requeues 0 
    --
     |             rate 0bit 0pps backlog 0b 0p requeues 0 
     |     
     +---(10:1965) htb prio 1 rate 50Mbit ceil 50Mbit burst 1600b cburst 1600b 
     |             Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0) 
     |             rate 0bit 0pps backlog 0b 0p requeues 0 
    ```
    可以看到，限速的队列带宽没有问题，上行20M，下行50M

2. 测速结果，上行8.05M、下行8.91M，完全不在同一水平上么
    这时候，我发现" Send 0 bytes 0 pkt "，而且上下行数据都是0，这说明流量根本就没走到这个队列！

3. 考虑到限速映射过程只有两个步骤，标记、映射，先检查标记部分：
    ```
    []@vser:~$ sudo iptables -t mangle -L -v
    Chain POSTROUTING (policy ACCEPT 56G packets, 57T bytes)
    pkts bytes target     prot opt in     out     source               destination         
    18G 2164G IPMARK     all  --  any    any     10.151.0.0/18        anywhere             -j IPMARK --addr src  --and-mask 0xfff 
    16G   27T IPMARK     all  --  any    any     anywhere             10.151.0.0/18        -j IPMARK --addr dst  --and-mask 0xfff 
    ```

    看到这个结果就知道是哪里出问题了。地址池使用了18位掩码，就意味着变化的部分是后14位，如果使用0xfff掩码计算用户的mark值，就会导致部分高地址用户被映射到低位区间，跟其他用户冲突。按测试账号的数据，10.151.25.99，刚好是超出范围的高位IP用户，实际会被标记为 0965，与10.151.9.99用户共用了一个限速队列。

    当9.99这个用户在线的时候，两人实际上共用同一个队列，共享带宽，这就是有时候测速接近20M的原因，9.99用户使用的是20M套餐；而当9.99用户下线后，这个限速队列被重置为10Mbps，这时候测速就会出现先前的数据：上行8.05M、下行8.91M 。

4. 问题找到后，对IPMARK代码做了修改，
    ```
    iptables -t mangle -A POSTROUTING -s 10.151.0.0/18 -j IPMARK --addr src --and-mask 0x3fff
    iptables -t mangle -D POSTROUTING 1
    ```

    这样再测试先前的账号，已经可以看到对应的 10:1965 队列已经有流量经过：
    ```
         |     
     +---(10:1965) htb prio 1 rate 10Mbit ceil 10Mbit burst 1600b cburst 1600b 
     |             Sent 162249444 bytes 1574854 pkt (dropped 0, overlimits 0 requeues 0) 
     |             rate 0bit 0pps backlog 0b 0p requeues 0 
    --
     |             rate 0bit 0pps backlog 0b 0p requeues 0 
     |     
     +---(10:1965) htb prio 1 rate 20Mbit ceil 20Mbit burst 1600b cburst 1600b 
     |             Sent 1362668930 bytes 1770932 pkt (dropped 0, overlimits 0 requeues 0) 
     |             rate 0bit 0pps backlog 0b 0p requeues 0 
    ```

5. 修改后的测试结果是，speettest站点测速，下行只有27.58Mbps，上行为 11.30Mbps，仍然离实际限速值差距较大。
为了排查问题，对这个账号的限速参数做了调整，先后尝试了80M、8M、20M
    ```
    sudo tc class replace dev ens3f0 parent 10:1 classid 10:1995 htb rate 80Mbit ceil 80Mbit prio 1
    sudo tc class replace dev ens3f0 parent 10:1 classid 10:1995 htb rate 8Mbit ceil 8Mbit prio 1
    sudo tc class replace dev ens3f0 parent 10:1 classid 10:1995 htb rate 20Mbit ceil 20Mbit prio 1
    ```
    测试结果显示，限速值较小时，测速结果接近限速数据，比如8M测速为6.99M，20M被限速为 16.97M； 当速率较大的时候，速率差距就很大了，比如80M测速为 24M。再看tc队列状态，每次测速，对应的tc队列数据都会增加，说明数据确实在这个队列被限速。但是对应的dropped数据始终为0，说明数据不是在这个被丢掉的。再加上当时系统负载比较低、测速时数据包延迟在7、8ms，可以推断不是在网关限速的。

6. 联系客服换个测速站试试，试验了360，测试50M限速情况下，实际测速 5.25 * 8 = 42Mbps，考虑封包损耗，可以认为接近限速值了。另外就是，tc的dropped字段也终于出现了非0值。

后续客服联系了speedtest的限速，请求排查限速的问题，怀疑是测速站点被限速了，但在等反馈结果。

## 总结
1. mark参数问题：最早设计时，单网关考虑4096个设备，准备采用20位地址掩码，这样计算用户的mark值只需要0xfff就够了。但是后期发现，尽量给同一账号的用户分配相同地址，这样实际占用的地址数多于在线用户数，最终使用了18位地址掩码、16384个地址，相应的mark掩码就需要调整为0x3fff。但是，部署发现问题后，只在master基线修改了代码，并没有更新部署包。新服务部署时，一般不会去检查、修改某个特殊的参数；在小规模测试时，也不会触发这个问题（登录设备大于4096才会触发问题），所以直到用户规模足够，才发现了问题。

2. 测速反应的是客户端到测速服务器的速度，只要360能达到限速值，就说明网关没限速；但对用户来说速率实际没有达到标称值。

## 改进措施
1. 修改参数后，应及时评估相关改动，对所有涉及的数据做检查，修正数据；
2. 修复Bug后，应及时发布新版本修改问题，整理升级脚本；
3. 服务部署的版本应该登记、管理：在发现新Bug后，应该评估影响的服务器，对所有相关服务尽快执行升级；
