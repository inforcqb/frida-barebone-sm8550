# frida-barebone-sm8550

为 OnePlus Ace 2 Pro (PJA110) / SM8550 编译 [Frida 17.17.0](https://frida.re/news/2026/08/05/frida-17-17-0-released/) 的
**barebone agent 内核模块 `frida-agent.ko`**（把 GumJS/QuickJS 运行时整体跑进内核，做内核级 hook）。

- 内核：`5.15.180-android13-8-o-01176-g6333b0dbc8ed`（GKI 5.15 + OnePlus，LTO + CFI + BTF + SCS）
- 构建：GitHub Actions + DDK 容器 `ghcr.io/ylarod/ddk-min:android13-5.15-20260313`（kbuild 用）
- 内核配置已满足（已核对真机 `/proc/config.gz`）：
  - `CONFIG_KPROBES=y`
  - `CONFIG_KALLSYMS_ALL=y`
  - `CONFIG_SHADOW_CALL_STACK=y`（arm64 保留 x18 → `-ffixed-x18` / `-Zfixed-x18`）
  - `# CONFIG_MODULE_SIG_FORCE is not set`（允许未签名模块）

## 构建

手动触发 `build-frida-barebone` workflow，产物 `frida-agent.ko`。

构建分两半（见 [frida-core 的 README](https://github.com/frida/frida-core/blob/main/src/barebone/agent/linux/README.md)）：
1. **prelink**：Rust 静态库 + GumJS devkit + picolibc（soft-float），`ld -r` 合成一个可重定位目标；
2. **kbuild**：把预链接目标交给 DDK 内核树，生成 vermagic/modinfo/CRC 都正确的 `frida-agent.ko`。

## 加载与使用

```sh
adb push frida-agent.ko /data/local/tmp/
adb shell su -c "insmod /data/local/tmp/frida-agent.ko"
adb shell su -c "dmesg | grep frida"   # frida: listening on /dev/frida
```

然后：

```sh
# 设备上起 frida-server（barebone backend）
FRIDA_BAREBONE_CONFIG=/data/local/tmp/linux-kmod.json \
  frida-server --device barebone -l 127.0.0.1:27042

# 宿主机（adb forward tcp:27042 tcp:27042）
frida -H 127.0.0.1:27042 -p 0
```

`linux-kmod.json` 配置在 frida-core 的 `src/barebone/agent/etc/linux-kmod.json`。

## 参考

- [frida-core src/barebone/agent/linux/README.md](https://github.com/frida/frida-core/blob/main/src/barebone/agent/linux/README.md)
- [Frida 17.17.0 Released](https://frida.re/news/2026/08/05/frida-17-17-0-released/)
