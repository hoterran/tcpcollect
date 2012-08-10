#mysqlpcap

watch sql base libpcap


##dependency
lipcap


##compile

	gcc -g -o mp mysqlrstat.c -lpap


##use

	sudo ./mp

	2012-8-9 21:27:1 [3] select 1

	2012-8-9 21:27:3 [3] select * from d

	2012-8-9 21:27:5 [3] SELECT DATABASE()

	2012-8-9 21:27:5 [2] test

	2012-8-9 21:27:6 [3] select * from d


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


##output format:

	timestamp [commandType] sql


##TODO

###response_time
	each sql latency 

###resultset
	each sql result set


