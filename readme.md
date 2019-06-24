# 计网课设

## 基础功能 
* -v : 使ping处于verbose方式，它要ping命令除了打印ECHO-RESPONSE数据包之外，还打印其它所有返回的ICMP数据包

## 已实现功能
* -h : 显示帮助信息

* -b : 允许ping一个广播地址

* -t : 设置TTL(Time To Live)为指定的值。该字段指定IP包被路由器丢弃之前允许通过的最大网段数
 
* -q : 不显示任何传送封包的信息，只显示最后的结果

* -c : 发送count次ECHO_REQUEST（回传请求）数据包。当有deadline选项（最后期限，-w选项），在超时之前，ping等待                ECHO_REPLY（回传响应）直到count次

* -i : 设定间隔几秒发送一个ping包，默认一秒ping一次

* -s : 指定每次ping发送的数据字节数，默认为“56字节”+“28字节”的ICMP头，一共是84字节；
        包头+内容不能大于65535，所以最大值为65507（linux:65507, windows:65500）

* -n : 不要将ip地址转换成主机名

* -d : 使用Socket的SO_DEBUG功能

* -w : deadline, 等待时间

* -S : Set socket sndbuf. If not specified, it is selected to buffer not more than one packet

* -W : 以毫秒为单位设置ping的超时时间

* -f : 极限检测，快速连续ping一台主机，ping的速度达到100次每秒

* -l : 设置在送出要求信息之前，先行发出的数据包

* -a : audible ping(其实就是每次嘀嘀嘀)

* -A : 自适应ping，根据ping包往返时间确定ping的速度, 在rtt 较小的网络上接近于flood