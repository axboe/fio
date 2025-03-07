all: clean m2sw1-128k-sdb-randwrite-para.results_bw.log io bandwidth

m2sw1-128k-sdb-randwrite-para.results_bw.log:
	tar -xf fio-logs.tar.gz

io: setup
	./fio2gnuplot.py -p 'm2sw1-128k-*-read-para*iops.log' -g

bandwidth: setup
	./fio2gnuplot.py -p 'm2sw1-128k-*-read-para*bw.log' -g

setup:
	ln -sf ../*py ../*gpm .

clean:
	rm -rf *png mygraph mymath *py *gpm gnuplot_temp_file* *~
	rm -rf *.average *.stddev *.min *.max *.global
	rm -rf m2sw1-128k-read-para-bw m2sw1-128k-read-para-iops
	rm -rf *log
