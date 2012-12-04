#mysqlpcap

watch sql base libpcap

我们经常的在 MySQL 里不停的执行``show processlist``想了解最近执行的 sql 语句状况，可常常拿不到我们想要的结果。

mysqlpcap 是一个基于 pcap 用于观察 sql 语句执行情况的工具。它能够了解到经过某个 MySQL 实例的 sql 语句以及 sql 影响的行数，还有 sql 的响应时间。

新增功能，目前已经支持 prepare statement。

##compile

	make

##use

	sudo ./mysqlpcap

![use](https://raw.github.com/hoterran/tcpcollect/master/mysqlpcap.png)

## 只抓取某个用户的sql，逗号分割
	sudo ./mysqlpcap -u root,user1

## 过滤某些用户的sql，逗号分割
	sudo ./mysqlpcap -n user1,user2

## 针对某个ip的sql的抓取
	sudo ./mysqlpcap -l 1.1.1.1

## 针对某个port的sql抓取
	sudo ./mysqlpcap -p 3001

##output format

	timestamp           sql                                     latency(us)     rows            
	---------           ---                                     -----------     ---             
	9:22:33:815114      select 1                                291             1               
	9:22:39:167115      select * from d limit 20000             229             -2              
	9:22:39:167115      select * from d limit 20000             571             -2              
	9:22:39:167115      select * from d limit 20000             707             -2              
	9:22:39:167115      select * from d limit 20000             3508            -2              
	9:22:39:167115      select * from d limit 20000             3628            -2              
	9:22:39:167115      select * from d limit 20000             3675            20000           
	9:22:45:227112      desc d                                  47891           3               
	9:22:54:678621      insert into d values(1,2,3), (3,4,5)    33719           2    

1. timestamp MySQL服务器接收到 sql 的时间。
2. sql
3. latency(us) 响应时间，MySQL服务器返回结果集的时间与timestamp的差值。由于结果集可能分多个``tcp packet``发送过来。
所以存在多条记录。
4. 对于``select``语句则是结果集的行数，对于其它则是影响的行数。结果集超过一个``tcp packet``的大小，则行数显示在最后一个``tcp packet``对应的记录上。 上面的例子，select * from d limit 20000 返回的结果集由 6 个``tcp packet``组成，所以有 6 行记录，前5行的 rows 为 -2 ，最后一行的 20000 才是真是的返回行数。 latency显示的每个tcp packet 的响应时间。

5. 第五列是用户
6. 如果是 prepare statement 则值会显示在 sql 的后面，用方括号包围住。


## prepare statement 的支持

![use](https://raw.github.com/hoterran/tcpcollect/master/mysqlpcap-prepare.png)

sql 在前面，方括号里为具体的值。

## TODO
* keyword filter
* output threading
* pf_ring
* multi stmt

##changelog

* user
* latency
* rows
* sql
* log
* prepare
* multi session big resultset
* support bond netcard
* support show src ip (-z)
* support drop packet and chao order packet
* ignore remote MySQL port connect me random port, data, for example: replication,
* ignore me connect rmeote MySQL data
* support specify detail ip (-l)
* support bond card repeat packet(same seq)
* support user level sql capture

##version
0.01
