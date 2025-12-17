# mini_esp
实现2端最小ESP加密

编译与运行:
cd kernel && make && sudo insmod mini_esp_perf.ko
cd ../user && make
sudo ./mini-ctl add 0x101 10.0.0.2 55555 \
00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
iptables -t mangle -A OUTPUT -j MARK --set-mark 0x101
