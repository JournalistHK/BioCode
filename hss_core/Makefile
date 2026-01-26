CC = gcc

# ==============================================================================
# OpenSSL 路径配置
# ==============================================================================
# 为了同时兼容不同架构的 Mac，我们在此列出了两个常见的 OpenSSL 安装路径：
# 
# 1. /usr/local/opt/openssl   -> Intel 芯片 Mac 的默认 Homebrew 路径
# 2. /opt/homebrew/opt/openssl -> Apple Silicon (M1/M2/M3) 芯片 Mac 的默认路径
#
# 注意：在编译时，链接器可能会针对不存在的路径发出 "search path not found" 警告。
# 这是正常的，只要其中一个路径有效，程序就能正确链接。
# ==============================================================================

CFLAGS = -Wall -O2 -I. \
         -I/usr/local/opt/openssl/include \
         -I/opt/homebrew/opt/openssl/include

LDFLAGS = -L/usr/local/opt/openssl/lib \
          -L/opt/homebrew/opt/openssl/lib \
          -lcrypto

all: hss_nim_test

# --- NIM Core Tests ---
hss_nim_test: hss_core.o hss_test.o
	$(CC) $(CFLAGS) -o hss_nim_test hss_core.o hss_test.o $(LDFLAGS)

# --- Object Files ---
hss_core.o: hss_core.c hss_core.h hss_config.h
	$(CC) $(CFLAGS) -c hss_core.c

hss_test.o: hss_test.c hss_core.h hss_config.h
	$(CC) $(CFLAGS) -c hss_test.c

clean:
	rm -f *.o hss_nim_test