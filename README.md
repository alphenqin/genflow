# genflux

纯 Go CLI：用于生成和回放 pcap（AF_PACKET）。

## 功能概述

- 生成合成 pcap（模拟内外网主机、随机流量分布）
- 回放 pcap（按原始时间戳/固定 Mbps/固定 PPS）

## 构建

```
go build -o genflux ./cmd/genflux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o genflux ./cmd/genflux
```

## 运行

### 1) 生成合成 pcap

示例 A：生成 1 个文件，默认命名 `generated_0000.pcap`

```
./genflux pcap gen --file-count 1 --out-dir .
```

示例 B：生成 5 个文件，控制起始时间与大小

```
./genflux pcap gen \
  --file-count 5 \
  --out-dir ./out \
  --start-time \"2024-01-01T00:00:00Z\" \
  --max-size 100000000
```

示例 C：生成固定 200 万条 5 元组流（每条 10 包）

```
./genflux pcap gen \
  --flow-count 2000000 \
  --packets-per-flow 10 \
  --internal-hosts 1000 \
  --external-hosts 1000 \
  --max-size 1600000000 \
  --file-count 1 \
  --out-dir .
```

示例 D：按固定 200 Mbps 回放（单次）

```
sudo ./genflux replay --in generated_0000.pcap --iface eth0 --mode mbps --mbps 200 --loop 1
```

```
./genflux pcap gen \
  --internal-hosts 50 \
  --external-hosts 500 \
  --min-duration 60 \
  --max-duration 120 \
  --file-count 1 \
  --out-dir .
```

常用参数：
- `--internal-hosts`：内部主机数量。内部网默认 192.168.0.0/16。
- `--external-hosts`：外部主机数量。外部网随机 IPv4。
- `--min-duration`：最小时长（秒）。
- `--max-duration`：最大时长（秒）。
- `--file-count`：生成文件数量（>1 时文件名为 `generated_000000.pcap` 等）。
- `--out-dir`：输出目录。
- `--start-time`：开始时间（RFC3339 或 `Mon Jan 2 15:04:05 2006`）。
- `--max-size`：单文件最大字节数（用于控制总包数上限）。
- `--seed`：随机种子（int64），用于复现实验结果。

### 2) 回放 pcap（AF_PACKET）

示例 A：按原始时间戳回放

```
sudo ./genflux replay --in input.pcap --iface eth0 --mode timestamp
```

示例 B：固定 1Gbps 速率回放

```
sudo ./genflux replay --in input.pcap --iface eth0 --mode mbps --mbps 1000
```

示例 C：固定 50k PPS 回放，循环 10 次

```
sudo ./genflux replay --in input.pcap --iface eth0 --mode pps --pps 50000 --loop 10
```

```
sudo ./genflux replay --in input.pcap --iface eth0 --mode timestamp
sudo ./genflux replay --in input.pcap --iface eth0 --mode mbps --mbps 1000
sudo ./genflux replay --in input.pcap --iface eth0 --mode pps --pps 50000
```

常用参数：
- `--in`：输入 pcap。
- `--iface`：网卡名称（如 `eth0` / `ens3`）。
- `--mode`：回放速率控制模式：
  - `timestamp`：按 pcap 原时间戳间隔发送。
  - `mbps`：按固定 Mbps 发送。
  - `pps`：按固定 pps 发送。
- `--mbps`：固定速率（Mbps），当 `mode=mbps` 必填。
- `--pps`：固定速率（pps），当 `mode=pps` 必填。
- `--loop`：循环次数（0=无限）。
- `--limit`：总发送包数上限（0=不限，跨循环累计）。
- `--stats-interval`：统计间隔秒（默认 1）。

## 环境要求

- Linux（AF_PACKET 仅支持 Linux）
- 回放需要 root 或 `CAP_NET_RAW` 权限
- pcap 建议为以太网链路层（DLT_EN10MB）

## 常见问题

- 为什么回放需要 root？
  - AF_PACKET 发送原始以太帧，需要 `CAP_NET_RAW`。
- 能否回放 TCP/UDP？
  - 可以，回放是按 pcap 原始帧发送，不区分 TCP/UDP。


200mbps 无限打
  sudo ./genflux replay --in generated_0000.pcap --iface eth4 --mode mbps --mbps 200 --loop 0
约 200MB 的 pcap，循环时单次更长
  ./genflux pcap gen --file-count 1 --out-dir . --max-size 200000000 --min-duration 60 --max-duration 60
