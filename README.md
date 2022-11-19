# sysprobe

一个可动态配置的系统事件探针

## 控制信道

作为服务端监听外部请求,并给出响应.外部请求可能是配置变更请求,也可能是状态查询请求.

## 数据信道

作为客户端向特定套接字单向写入数据.

## 许可证

eBPF 代码使用 [GPL-2.0](https://spdx.org/licenses/GPL-2.0-only.html) 许可证.
其他部分使用 [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) 许可证.
