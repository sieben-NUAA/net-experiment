# net-experiment
南航智能网络与计算实验

#实验一：PING程序的实现
> ##### 实验目的：理解ping程序的概念，熟练使用原始套接字
> ##### 实验环境：Linux，C
> ##### 实验内容：
>- 设计一个简单的PING程序，每隔1秒钟使用ICMP报文向目的IP地址发一个ICMP请求（长度由length指定），对方将返回一个ICMP应答，应答数据包通过循环调用函数recvfrom来接收。发送ICMP报文的次数由counts指定
>- ping dstIP –l length –n counts
