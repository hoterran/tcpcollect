#mysqlpcap

watch sql base libpcap


##dependency

lipcap


##compile

	make


##use

	sudo ./mysqlpcap

![use](https://raw.github.com/hoterran/tcpcollect/master/mysqlpcap.png)

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



