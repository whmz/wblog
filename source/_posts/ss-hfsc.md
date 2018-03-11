---
title: 多用户环境下的流量标记
date: 2018-02-25 18:33:06
tags: 
---

单位使用了个Linux网关在园区网络提供旁路接入功能。作为运营网络，肯定得考虑限速的问题，使用了iptables、IPMARK、tc-htb等功能实现了限速。

随着用户数逐渐增多，当出口网络比较拥堵的时候，大量用户反馈延迟较高、游戏用户基本无法使用。基于这样的情况，我们尝试是否能在当前的系统上，增加QoS支持：区分用户的应用流量、执行不同速率策略，缓解问题。

本文简单记录了两个试验方案，使用HTB和HFSC限速和整流，给出限速的关键脚本和思路，以及配套的MARK规则。本文先不讨论HTB、HFSC本身的使用方法和设计，主要讨论分类器的设计和实现。

## 基于用户的限速
策略比较简单，每个接入用户使用自己的htb-class：
* 在用户接入的时候，Radius模块能收到用户的接入IP、上下行带宽数据，根据这些数据设置htb-class的限速参数
* 当用户有网络流量经过网关时，根据IP把对应的流量映射到htb-class

在具体代码上，大致有这么三段：
1. 通过iptables-mark标记流量
    ```
    # 根据流方向，用户上下行有两条规则.对于用户输入流量，假定用户IP为 srcIP ，则 
    # mark = srcIP & 0xff

    iptables -t mangle -A POSTROUTING -s $VIPS -j IPMARK --addr src --and-mask 0xfff
    ```

2. tc初始化    
    ```
    # 定义用户流量映射规则
    # 以mark为key，映射用户流量到 10:(1+mark) 分类

    tc filter add dev $ODEV parent 10: handle 100 flow map key mark baseclass 10:1 
    ```

3. tc限速设置
    ```
    # 用户IP为vip，计算其vflag，对10:$vflag分类设置速率值，其中
    # vflag = ($vip + 1) & 0xfff

    tc class replace dev $ODEV parent 10:1 classid 10:$vflag htb rate $urate ceil $uceil prio 1
    ```
## 基于用户+QoS的限速
根据我们的分析，除了扩大出口流量，试试对用户流量分级、降低大流量应用的优先级、保障游戏、交互带宽，应该也能缓解部分问题。

相对简单的用户限速方案，这个方案要在识别用户流量的基础上，进一步识别应用。考虑我们的流量规模大致在5~10Gbps，在这样的网络环境下要实现应用流量识别、再加以QoS限速，从性能上讲不大现实——算法太复杂，算法本身对性能的影响太大，会进一步加大延迟。

内部讨论后，我们基于包长度做了个简单的模型。除了数据包本身的QoS字段之外，包长度在一定程度上也能反映用户数据流量的特征：大数据传输一般使用最大报文长度；TCP初始连接、交互数据一般不会有太大的数据量，从而数据包长度较短。

考虑这个情况，我们的需求1：
    ```
    设计一个相对简洁的标记机制，区分同一用户下的流量，使得针对不同的流量能施加不同的速率控制
    ```

另外，用户接入过程也会占用一部分流量，这部分流量因为未纳入限速框架（用户接入成功前IP不在$VIP定义的地址池中），默认会归为系统流量。如果不给这部分流量保留带宽，用户在高峰期的连接成功率会比较差。需求2来了：
    ```
    新的流量标记机制，必须区分系统带宽和用户带宽，对系统带宽也进行分类，对接入流量和其他流量设置不同策略。
    ```

基于这两个需求，我们设计了这样的一个MARK规则（请忽略长度数据....）：
    ```
    # length < 400
    1.  iptables -t mangle -A POSTROUTING -d $VIPS -m length --length :400 -j IPMARK --addr dst --and-mask 0x3fff --or-mask 0x24000
    2.  iptables -t mangle -A POSTROUTING -d $VIPS -m length --length :400 -j RETURN

    # length > 400
    3.  iptables -t mangle -A POSTROUTING -d $VIPS -j IPMARK --addr dst --and-mask 0x3fff --or-mask 0x28000
    4.  iptables -t mangle -A POSTROUTING -d $VIPS -j RETURN

    # sys load
    5.  iptables -t mangle -A POSTROUTING -m length --length :400 -j IPMARK --set-mark 0x14000
    6.  iptables -t mangle -A POSTROUTING -m length --length :400 -j RETURN

    7.  iptables -t mangle -A POSTROUTING -j MARK --set-mark 0x18000
    8.  iptables -t mangle -A POSTROUTING -j RETURN
    ```
按设计想法，用户流量符合$VIPS地址池条件，会在前面的四条规则中被设置为 ((ip & 0x3fff) | 0x24000) 或者 ((ip & 0x3fff) | 0x24000)，系统流量则归为 0x14000 和 0x18000 ，从而实现上述两个需求。同时，符合一条规则的包不再执行后续的检查，从性能上讲也好一点。

但是，实际测试时候发现，所有包都被纳入了 0x14000 和 0x18000 这两个分类！
为了跟踪包标记情况，使用了iptables -t mangle -L -v，查看了每条规则的包匹配情况，发现每个经过1、2的包，都会再次经过5、6; 而3、4两条规则也是一样，再次经过7、8。这样的话，每个包被标记了两次，肯定是后一个标记起作用。

那么问题是，为什么包在规则2、4行的RETURN之后，还会继续经过后续的5、6、7、8规则呢？原来，我们的接入方式是IPSec，一个网络包进入网卡后，会根据数据方向，通过XFRM框架解包/封包，在协议栈内部实际跑两圈，两次经过mangle postrouting链。在用户下行数据方向，就会出现刚才的情况，实际上所有流量都会走到系统队列处理。这个可以参考[Netfilter-packet-flow](https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-flow.svg)

为了解决这个问题，修改后的的MARK规则是这样的:
    ```
    # ip addr
    iptables -t mangle -A POSTROUTING -d $VIPS -j IPMARK --addr dst --and-mask 0x3fff --or-mask 0x20000

    # load length
    iptables -t mangle -A POSTROUTING -m length --length :400 -j MARK --or-mark 0x14000
    iptables -t mangle -A POSTROUTING -m length --length :400 -j RETURN

    iptables -t mangle -A POSTROUTING -j MARK --or-mark 0x18000
    iptables -t mangle -A POSTROUTING -j RETURN
    ```
按这个规则，地址池$VIPS中的地址包，会在原有的mark基础上添加一个0x20000; 所有的包都会根据包长度，在原有mark上添加一个 0x14000 或 0x18000 。这样，用户包，始终都会经过两次mark标记，最终结果为 0x34000 或 0x38000 ；系统包因为不会满足$VIPS的地址池条件，其mark只能是 0x14000 或 0x18000 。该标记满足了上述两个需求。

但是这样一来，每个用户包已经至少多执行3条过滤规则

## 需要进一步学习的内容
hfsc限速参数中，rt、ls、ul、sc的含义和相互关系。
