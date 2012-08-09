#tcp collect

unstable....


#use

#compile

	gcc -g -o x mysqlrstat.c -lpap

	sudo ./x
	2012-8-9 21:20:46 caplen:79 len:79 127.0.0.1:46530->127.0.0.1:3306 ip_total_bytes:65 3 select 1
	2012-8-9 21:20:49 caplen:79 len:79 127.0.0.1:46530->127.0.0.1:3306 ip_total_bytes:65 3 select 1

