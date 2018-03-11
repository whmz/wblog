---
title: Strongswan-DAE功能相关逻辑整理
date: 2018-03-11 21:17:06
tags: 
---

## 目录

1. 概念
    * DAE（Dynamic Authorization Extensions，动态授权扩展）协议是RFC 5176中定义的RADIUS协议的一个扩展，它用于强制认证用户下线，或者更改在线用户授权信息。DAE采用客户端/服务器通信模式，由DAE客户端和DAE服务器组成。

        DAE客户端：用于发起DAE请求，通常驻留在一个RADIUS服务器上，也可以为一个单独的实体。

        DAE服务器：用于接收并响应DAE客户端的DAE请求，通常为一个NAS（Network Access Server，网络接入服务器）设备。

    * DAE报文包括以下两种类型：

        DMs（Disconnect Messages）：用于强制用户下线。DAE客户端通过向NAS设备发送DM请求报文，请求NAS设备按照指定的匹配条件强制用户下线。

        COA（Change of Authorization）Messages：用于更改用户授权信息。DAE客户端通过向NAS设备发送COA请求报文，请求NAS设备按照指定的匹配条件更改用户授权信息。

        在设备上使能RADIUS DAE服务后，设备将作为RADIUS DAE服务器在指定的UDP端口监听指定的RADIUS DAE客户端发送的DAE请求消息，然后根据请求消息进行用户授权信息的修改或断开用户连接，并向RADIUS DAE客户端发送DAE应答消息。

2. Strongswan-DAE 问题分析
    * 现象
        * 某个用户登录认证连续多次提示已在线，踢下线没有效果；
        * 检查发现以下情况：
            * 日志显示：用户13：50：57 认证成功，13：50：59 下线成功
            * 用户13：50之后一直access-reject，直到14：30左右成功登录
            * radius处检查后，认为是进入会话异常呆死状态，根据已有逻辑，大概30分钟后才能结束该会话
            * 用户通过自理平台发起下线，14：09下线失败，返回 Dissconn-NAK；14：16有一次提示Dissconn-ACK，但是之后并没有实际踢下线；后续的踢下线都是NAK

    * 检查步骤和发现的问题
        * 网关日志检查
            * 确认用户13：50：57 认证成功，13：50：59 下线成功；下线时发送了Accounting-END，并且收到了Radius的响应报文
            * 确认14：16该用户有一次Dissconn-ACK报文，其他都是NAK

            结论：需要检查下Strongswan的DAE处理逻辑，看是什么问题

        * 使用Source Insight查看strongswan代码
            * 搜索dae代码会出现大量的daemon相关的代码，结果太多
            
            * 搜索dae、大小写敏感、只搜索注释部分，找到了DAE的处理文件：              \strongswan\src\libcharon\plugins\eap_radius\eap_radius_dae.c
            
            * 找到了DAE-disconn处理入口：process_disconnect，关键代码：
                * ids = get_matching_ike_sas(this, radius_message_t *request, client);
                    * 根据request的属性信息查找对应的ike_sa
                * 后续代码：
                    * 如果找到sa，则执行清理下线，发送给RMC_DISCONNECT_ACK报文；否则发送RMC_DISCONNECT_NAK。 打印日志信息的代码与日志匹配。确定是该处逻辑处理DAE
            
            * get_matching_ike_sas(this, radius_message_t *request, client):
                ``` enumerator = request->create_enumerator(request);
                    while (enumerator->enumerate(enumerator, &type, &data))
                    {
                        if (type == RAT_USER_NAME && data.len)
                        {
                            user = identification_create_from_data(data);
                            DBG1(DBG_CFG, "received RADIUS DAE %N for %Y from %H",
                                radius_message_code_names, request->get_code(request),
                                user, client);
                            add_matching_ike_sas(ids, user);
                            user->destroy(user);
                        }
                    }
                ```
                * 第一个关键点，处理dae-request时，仅使用了其中的RAT_USER_NAME数据，没有使用session-id... 结合用户行为，可以推测：
                    * 用户边执行重试拨号、边执行了自理平台的下线操作

                * 检查日志信息，发现有以下信息：
                    ```
                    14:16:13 charon: 20[CFG] received RADIUS DAE Disconnect-Request for 1769136.... from 59.110.24.89
                    14:16:13 charon: 20[CFG] closing 1 IKE_SA matching Disconnect-Request, sending Disconnect-ACK
                    14:16:13 charon: 26[IKE] destroying IKE_SA in state CONNECTING without notification
                    ``` 
                    网关认为是CONNECTING状态的会话，不需要做其他操作，因此不会给radius侧回复Account-END，这一点与Radius的日志信息匹配

                * 这个DAE使用用户名踢下线，具体会踢哪些会话，是否会全踢，还是只踢第一个：
                    ```
                    ids = get_matching_ike_sas(this, request, client);

                    if (ids->get_count(ids))
                    {
                        DBG1(DBG_CFG, "closing %d IKE_SA%s matching %N, sending %N",
                            ids->get_count(ids), ids->get_count(ids) > 1 ? "s" : "",
                            radius_message_code_names, RMC_DISCONNECT_REQUEST,
                            radius_message_code_names, RMC_DISCONNECT_ACK);

                        enumerator = ids->create_enumerator(ids);
                        while (enumerator->enumerate(enumerator, &id))
                        {
                            lib->processor->queue_job(lib->processor, (job_t*)
                                                    delete_ike_sa_job_create(id, TRUE));
                        }
                        enumerator->destroy(enumerator);

                        send_response(this, request, RMC_DISCONNECT_ACK, client);
                    }
                    else{
                        ...
                    }
                    ```
                    从代码看，get_matching_ike_sas返回的ids，都会执行清理操作。这一点需要注意，后续统一用户存在多个会话时，确实会存在误踢，把用户全部会话都踢掉

    * DAE-COA
        * 检查了COA的代码处理逻辑，process_coa,在处理时跟disconn一样，也只匹配了用户名字段，没有检查session-id是否一样。也就是说，后续如果启用COA功能，也面临一样的问题，会同时重置多个连接的在线时长。这一点可能还是有益的，当用户在线续费、或费用到期，可以同时停止或启用。

3. DAE和超时时间
    在实际执行中，发现有时候用户执行踢下线操作时，会延迟很长时间（几分钟），实际的下线操作才会成功。根据用户ID、IP、会话信息查找具体的会话DAE过程，发现这样一个情况：踢下线操作收到后，SS端先执行会话查找操作，找到会话后就发送ACK给Radius端，同时给会话的另一端发送一个断开连接的请求；如果用户还在线则很快响应这个报文下线；如果用户已经断开了网络（断开原先链接的Wifi、非断开IPSec连接），则会重发多次报文之后，才会执行断开操作。而只有断开操作成功后，才会给Radius端发送记账结束报文。

    以下是超时时间的选择：
    ```
    # /etc/strongswan.d/charon.conf

    # Base to use for calculating exponential back off, see IKEv2 RETRANSMISSION
    # in strongswan.conf(5).
    # retransmit_base = 1.8

    # Timeout in seconds before sending first retransmit.
    retransmit_timeout = 4.0

    # Number of times to retransmit a packet before giving up.
    retransmit_tries = 5

    # Interval to use when retrying to initiate an IKE_SA (e.g. if DNS
    # resolution failed), 0 to disable retries.
    # retry_initiate_interval = 0
    ```

    通过man strongswan.conf 查找了超时时间一节：
    ```
    IKEv2 RETRANSMISSION
       Retransmission timeouts in the IKEv2 daemon charon can be configured globally using the three keys listed below:

              charon.retransmit_base [1.8]
              charon.retransmit_timeout [4.0]
              charon.retransmit_tries [5]
              charon.retransmit_jitter [0]
              charon.retransmit_limit [0]

       The following algorithm is used to calculate the timeout:

            relative timeout = retransmit_timeout * retransmit_base ^ (n-1)

       Where  n  is  the  current  retransmission count. The calculated timeout can't exceed the configured retransmit_limit (if
       any), which is useful if the number of retries is high.

       If a jitter in percent is configured, the timeout is modified as follows:

            relative timeout -= random(0, retransmit_jitter * relative timeout)

       Using the default values, packets are retransmitted in:

       Retransmission   Relative Timeout   Absolute Timeout
       ─────────────────────────────────────────────────────
       1                              4s                 4s
       2                              7s                11s
       3                             13s                24s
       4                             23s                47s
       5                             42s                89s
       giving up                     76s               165s
    ```
    根据我们跟踪的日志信息，发下上述时间跟日志输出的时间间隔一致。考虑到安全问题，IPSec这样设计超时也许没问题，在我们的接入应用中，这么长的超时时间没法接受，我们把两个参数修改了
    ```
    # Timeout in seconds before sending first retransmit.
    retransmit_timeout = 3.0

    # Number of times to retransmit a packet before giving up.
    retransmit_tries = 3
    ```

    根据它的超时算法，修改后的超时时间为：
    ```
    Retransmission   Relative Timeout   Absolute Timeout
    ─────────────────────────────────────────────────────
    1                              3s                 3s
    2                            5.4s               8.4s
    3                            9.7s              18.1s
    giving up                   17.5s              35.6s
    ```
    这样已经能兼顾丢包和处理效率，在局域网内效果已经可以保证。

4. 如何根据DAE获取并匹配session-id
    后续如果需要修改这块的逻辑，需要根据DAE报文中的session-id，查找ike_sa，应用新的授权信息。

    * 已有的dae代码已经能根据用户名获取到用户名匹配的ike_sa

    * SESSION-ID
        * 根据radius的DAE报文，找到了session-id对应的attribute-type：\strongswan\src\libradius\radius_message.h,
            * RAT_ACCT_SESSION_ID = 44,
        
        * 初始化:
            在发送Accounting-Start时开始获取或创建：get_or_create
            ```
            /**
            * Send an accounting start message
            */
            static void send_start(private_eap_radius_accounting_t *this, ike_sa_t *ike_sa)
            {
                ...
                
                entry_t *entry;
                
                ...

                entry = get_or_create_entry(this, ike_sa->get_id(ike_sa),
                                            ike_sa->get_unique_id(ike_sa));

            ```
            创建时，实际调用了这些操作(unique会记录到syslog中)：
            ```
            snprintf(entry->sid, sizeof(entry->sid), "%u-%u", this->prefix, unique);
            ```

            其中的prefix信息是这么生成的：
            ```
            eap_radius_accounting_t *eap_radius_accounting_create()
            {
                ...

                /* use system time as Session ID prefix */
                .prefix = (uint32_t)time(NULL),

                ...
            ```
            
            unique_id是个递增的值，每创建一个ike_sa加1：
            ```
            ike_sa_t * ike_sa_create(ike_sa_id_t *ike_sa_id, bool initiator,
                    ike_version_t version)
            {
                private_ike_sa_t *this;
                static refcount_t unique_id = 0;

                .unique_id = ref_get(&unique_id),
            ```
            ```
            /**
            * Increase refcount
            */
            refcount_t ref_get(refcount_t *ref)
            {
                refcount_t current;

                ref_lock->lock(ref_lock);
                current = ++(*ref);
                ref_lock->unlock(ref_lock);

                return current;
            }
            ```

    * 参考上述代码，仿照get_or_create 功能，仅使用get部分的代码：
        * \src\libcharon\plugins\eap_radius\eap_radius_plugin.c: plugin_cb
        此处为已有代码，在创建dae时已经给赋值了accounting对象：
        ```
        this->accounting = eap_radius_accounting_create();
        this->forward = eap_radius_forward_create();
        this->provider = eap_radius_provider_create();

        load_configs(this);

        if (lib->settings->get_bool(lib->settings,
                        "%s.plugins.eap-radius.dae.enable", FALSE, lib->ns))
        {
            this->dae = eap_radius_dae_create(this->accounting);
        }
        ```

        在src\libcharon\plugins\eap_radius\eap_radius_accounting.c 中添加get_session_id方法(示例，后续要加锁)：
        ```
        static char * get_session_id(private_eap_radius_accounting_t *this,
                                    ike_sa_id_t *id)
        {
            entry_t *entry;
            entry = this->sessions->get(this->sessions, id);
            return entry->sid; //char sid[24];
        }
        ```

        在src\libcharon\plugins\eap_radius\eap_radius_dae.c中需要使用sid的地方调用(示例，后续要加锁、要判断是否为空)：
        ```
        static char * get_session_id(private_eap_radius_dae_t *this,
                                ike_sa_id_t *id)
        {
            return this->accounting->get_session_id(this->accounting,id);
        }
        ```

5. 其他发现
    * account-stop 通过触发方式调用，在连接断开时，通过 up_down 调用
    * 发送accounting时，会附带RAT_NAS_IP_ADDRESSs属性，这个值一般情况下是提供VPN服务的端口IP；当用户通过非园区网络连接时，也就是用户网络切换后，如果服务器到用户的路由切换到外网口，这个值会变成对应的外网口IP：
        ``` 
    	Acct-Session-Id = "1514557340-10756"
       	NAS-IP-Address = 218.195.95.16
        Called-Station-Id = "218.195.95.16[4500]"
        Calling-Station-Id = "172.17.57.196[60232]"
        ```
        ```
    	Acct-Session-Id = "1514557340-10756"
        NAS-IP-Address = 111.21.65.2
        Called-Station-Id = "111.21.65.2[4500]"
        Calling-Station-Id = "113.200.106.45[25978]"
        ```
    * 当网关收到用户侧发过来的数据时，会根据src和dst更新ike_sa中的host信息
