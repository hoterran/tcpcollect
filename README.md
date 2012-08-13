#mysqlpcap

watch sql base libpcap


##dependency

lipcap


##compile

	make


##use

	sudo ./mysqlpcap

	timetamp           sql                                     latency(us)     rows            
	---------           ---                                     -----------     ---             
	21:59:12:619629     select * from d limit 199               109             199             
	21:59:13:359634     select * from d limit 199               111             199             
	21:59:13:931641     select * from d limit 199               112             199             
	21:59:37:195648     select * from d limit 399               1324            399 

##parameter

-p mysql port
	./mp -p 3307

-i netcard device name, default is eth0, if cant find then bond0
	./mp -i bond1

-k keyword, you can use tablen name
	./mp -k order

-f write data into file
	./mp -f /tmp/mp.log

-d daemon

./mp -k order1 -p 3307 -f /tmp/mp.log -i eth1


##TODO

* field_packet length length code binary
* one resultset larger than one tcp packet



