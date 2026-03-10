.PHONY: all clean hss face_recognition benchmark test test-hss test-face test-benchmark test-precision

# 默认构建三个核心模块
all: hss face_recognition benchmark

# --- 单独构建各个模块 ---
hss:
	$(MAKE) -C hss_core

face_recognition:
	$(MAKE) -C face_recognition

benchmark:
	$(MAKE) -C benchmark

# --- 单独运行各个模块的测试/演示 ---
test-hss: hss
	@echo "\n=== Running HSS Core Tests ==="
	cd hss_core && ./hss_nim_test

test-face: face_recognition
	@echo "\n=== Running Face Recognition Demo ==="
	cd face_recognition && ./face_auth_demo

test-benchmark: benchmark
	@echo "\n=== Running Benchmarks ==="
	cd benchmark && ./nim_benchmark
	cd benchmark && ./face_benchmark

# 整体进行测试 (仅包含功能和性能基准)
test: test-hss test-face test-benchmark

# --- 独立的大规模精度与安全评估测试 ---
# 精度测试单独拿出来，因为它通常非常耗时且性质不同
test-precision: all
	@echo "\n=== Running Precision & Validation Tests ==="
	cd tests/precision_test && ./run_test.sh

# --- 清理所有构建产物 ---
clean:
	$(MAKE) -C hss_core clean
	$(MAKE) -C face_recognition clean
	$(MAKE) -C benchmark clean
	rm -f tests/precision_test/test_precision
	rm -f tests/precision_test/*.o
