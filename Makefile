# TencDRM 构建脚本 — 需要 Android NDK (r25+)
# 用法: make NDK=/path/to/android-ndk-r26d
NDK ?= $(error set NDK=/path/to/android-ndk, e.g. make NDK=/opt/ndk)
API  := 24
HOST := linux-x86_64
CC   := $(NDK)/toolchains/llvm/prebuilt/$(HOST)/bin/aarch64-linux-android$(API)-clang
CFLAGS := -O2 -fPIC -Wall

all: out/DRMID-inject out/DRMID-A.so out/DRMID-B.so

out/DRMID-inject: src/inject.c
	@mkdir -p out
	$(CC) $(CFLAGS) -fPIE -pie -o $@ $< -ldl

out/DRMID-A.so: src/drm_parcel_hook.c
	@mkdir -p out
	$(CC) $(CFLAGS) -shared -o $@ $< -llog

out/DRMID-B.so: src/wvhidl_hook.c
	@mkdir -p out
	$(CC) $(CFLAGS) -shared -o $@ $< -llog

clean:
	rm -rf out

.PHONY: all clean
