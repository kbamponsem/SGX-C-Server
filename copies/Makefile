start_server: 
	$(MAKE) all
	./objs/nginx

all: setup_enclaves build

clean:
	rm -rf Makefile objs
setup_enclaves:
	@cd /home/kwabena/TaLoS/src/nginx-1.11.0/nginx_sgx_bank/Enclave1 && $(MAKE) nginx_sgx
	@cd /home/kwabena/TaLoS/src/nginx-1.11.0/nginx_sgx_bank/Enclave2 && $(MAKE) nginx_sgx

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/home/kwabena/TaLoS/src/nginx-1.11.0/install/sbin/nginx -t

	kill -USR2 `cat /home/kwabena/TaLoS/src/nginx-1.11.0/install/logs/nginx.pid`
	sleep 1
	test -f /home/kwabena/TaLoS/src/nginx-1.11.0/install/logs/nginx.pid.oldbin

	kill -QUIT `cat /home/kwabena/TaLoS/src/nginx-1.11.0/install/logs/nginx.pid.oldbin`
