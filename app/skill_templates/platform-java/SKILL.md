---
name: platform-java
description: Java / JVM 告警诊断（Java 进程 CPU 或内存异常、频繁 GC、OOM、服务异常重启、启动参数不合理）：识别应用、启动命令与 JVM 参数，结合进程、cgroup 限制、GC 与日志交叉验证。告警类型为 java 或内存类告警时加载。
types: [java, memory]
prefetch:
- scopes: [alert, web, qa]
  types: [java]
  ssh: [ssh_diagnose_java, ssh_diagnose_memory, ssh_diagnose_memory_processes, ssh_diagnose_processes]
  zabbix_items: [jmx, proc.num, proc.mem, vm.memory]
  history: ["jmx*HeapMemoryUsage*", "jmx*GarbageCollector*", "jmx*", "proc.mem*", "vm.memory.utilization"]
  schemas: [history_get, trend_get]
---

# Java / JVM 诊断

## 识别进程

- `ssh_diagnose_java` 列出全部 Java 进程：PID、应用名（spring.application.name、jar 名或 systemd 单元）、主类或 JAR、运行时长、RSS、线程数、文件句柄、所属单元或容器、JDK 版本，以及 -Xms / -Xmx / MaxRAMPercentage / 元空间 / 直接内存 / GC 收集器参数与日志位置。启动命令已脱敏，报告中只引用需要的参数，不转述完整命令行。
- 进程以“应用名（PID）”称呼；应用名为“未识别”时写进程名与 PID，不猜测业务归属。

## 判断方法

- **内存**：RSS 与 -Xmx、cgroup 内存上限、主机 MemAvailable 一起看。未设置 -Xmx 且未设 MaxRAMPercentage（heap_max_unset）时 JVM 默认取物理内存或容器限制的 1/4，多实例共存容易挤爆内存；-Xmx 超过容器限制 90%（heap_exceeds_cgroup）必然被 OOM；RSS 远超堆上限（rss_far_above_heap）说明堆外、元空间、线程栈或直接内存占用。OOM 是否发生以 `ssh_diagnose_oom` / `ssh_diagnose_syslog` 的记录与服务重启历史为准。
- **堆外内存定位**：`jcmd <pid> VM.native_memory summary` 只在 JVM 启动参数含 `-XX:NativeMemoryTracking=summary`（或 detail）时可用，否则报 “Native memory tracking is not enabled”。启动参数里看不到该项时，建议写成“下次重启时加 -XX:NativeMemoryTracking=summary（约 5%–10% 性能开销）后用 jcmd 查看”，眼下可用 `pmap -x <pid>` 看大块匿名内存；需要堆的实际占用时自己调用 `ssh_diagnose_jvm`（heap_info）与 RSS 对比，不要写成人工建议。
- **CPU / GC**：Java 进程占用高时用 `ssh_diagnose_jvm`（pid 取自 ssh_diagnose_java，probes 默认 heap_info、vm_flags、gc_stat）看堆使用率、老年代占用、GC 次数与累计耗时：老年代接近满且 Full GC 次数持续增长、gc_time_ratio 高，说明 GC 压力导致 CPU 高或响应慢。jcmd 会让 JVM 短暂进入安全点，只在需要时对单个进程执行一次；GC 计数是启动以来的累计值，不是告警时段的速率。
- **重启与启动失败**：运行时长很短（recent_start）或单元 NRestarts 增加时，用 `ssh_diagnose_service_detail`（单元名来自 java 结果的 unit）看退出码、重启记录与启动日志，用 `ssh_diagnose_syslog` 按单元或 PID 查 OOM、启动异常。
- **线程与句柄**：线程数上千且持续增长、文件句柄接近上限（fds_near_limit）会导致请求堆积或 “Too many open files”。

## 报告要点

- 写清楚应用名（PID）、关键 JVM 参数与限制的对比、内存 / GC / 重启证据，以及参数调整建议的依据（例如“-Xmx 设为容器限制的 70%–75%”属于经验建议，需结合业务压测确认）。
- 建议里的命令要能在目标主机上直接执行：需要的启动参数、权限或工具不确定具备时写明前提，并给出前提不满足时的做法。
- 没有 GC 日志、jcmd 无法附加（attach_failed）或 JDK 工具缺失时，写明无法确认 GC 行为，不要推断内存泄漏。
