# eBPF

## Tracepoint

可用的 tracepoint 保存在 `/sys/kernel/debug/tracing/available_events`.

每行为一个 hook 点,格式为 `<category>:<name>`.

hook 点函数参数格式为 `/sys/kernel/debug/tracing/events/<category>/<name>/format`

按照以下方式定义 hook 函数.

```c
SEC("tp/<category>/<name>")
int function(void *ctx)
{
        return 0;
}
```

具体使用方法参考 [sysprobe.c](sysprobe.c)

## 网络模拟

清除模拟策略

```txt
tc qdisc del dev eth0 root netem
```

延时,乱序,丢包,重复,损坏

```txt
tc qdisc add dev eth0 root netem delay 100ms 20ms reorder 25% 10% loss 5% distribution normal duplicate 6% corrupt 7%
```
