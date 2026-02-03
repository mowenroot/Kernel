以下是作者的相关论坛主页

看雪论坛：[默文的看雪论坛](https://bbs.kanxue.com/user-1026022-1.htm)

先知论坛：[默文 的个人主页 - 先知社区](https://xz.aliyun.com/users/154057/news)



## Catalog

1. CVE-2022-2602
1. CVE-2023-2598
1. CVE-2024-0582
1. CVE-2021-1732
1. CVE-2021-40449

------

## Detail

#### 1. CVE-2022-2602

[writeup](https://xz.aliyun.com/users/154057/news)

**Test version**: Linux-5.18.19

**Protection**: 开启KASLR/SMEP/SMAP。

**Vulnerability**: 漏洞本质是 `filp` 的 `UAF` 。 `io_uring` 模块提供的 `io_uring_register` 系统调用中的 `IORING_REGISTER_FILES` 能注册文件。调用后会把**文件**放入 `io_uring->sk->receive_queue` 。在 `Linux gc` 垃圾回收机制中又会将该列表的文件取出，尝试会将文件取出并**释放**。导致下次使用 `io_uring` 利用该文件时会触发 `UAF` 。由于UNIX_GC垃圾回收机制会错误释放 `io_uring` 中还在使用的文件结构体（正在往`"/tmp/mowen"`普通文件写入恶意数据），可以**采用DirtyCred方法**，打开大量`"/etc/passwd"`文件，覆盖刚刚释放的`file`结构体，这样最后就会实际往`"/etc/passwd"`文件写入恶意数据。

![image-20250307145550639](./assets/image-20250307145550639.png)

#### 2. CVE-2023-2598

[writeup](https://xz.aliyun.com/users/154057/news)

**Test version**: Linux-6.3.1

**Protection**: 开启KASLR/SMEP/SMAP。

**Vulnerability**: 漏洞本质是**物理地址越界读取(oob)**。`io_uring` 模块中提供 `io_sqe_buffers_register` 来创建一个 `Fixed Buffers` 的区域，这块区域会锁定，不能被交换，专门用来数据的读取。但是在进行连续多个大页的优化，尝试合并页的时候，使用了新机制 `folio`，`folio` 是物理内存、虚拟内存都连续的 `page` 集合，在进行页合并时只判断 `page `是否属于当前复合页，而未判断是否连续。当用户传入同一个物理地址时，长度是整个复合页长度，地址是指向一个地址，这个时候就会造成**物理地址越界读取**。

![image-20250307145522257](./assets/image-20250307145522257.png)

#### 3.CVE-2024-0582

[writeup](https://xz.aliyun.com/news/17217)

**Test version**: linux-6.5.3

**Protection**: 开启KASLR/SMEP/SMAP。

**Vulnerability**: 漏洞本质是 `uaf`。从内核版本 **5.7** 开始，为了便于管理不同的缓冲区集，`io_uring` 允许应用程序注册由组 ID 标识的缓冲区池。通过 `io_uring_register`的 `opcode->IORING_REGISTER_PBUF_RING`调用 `io_register_pbuf_ring()` 来完成注册ID标识缓冲区。并从内核版本 **6.4** 开始，`io_uring` 还允许用户将提供的缓冲区环的分配委托给内核，由 `IOU_PBUF_RING_MMAP`标识符即可生成。调用 `IOU_PBUF_RING_MMAP` 由内核完成分配空间后，然后使用 `mmap()`标识符映射到用户的地址,但是这个操作不会修改**页面结构(pgae)的引用计数**，然后使用 `io_unregister_pbuf_ring()`释放申请的空间的时候会调用 `put_page_testzero(page)`，对 `page` 引用`-1`并判断引用是否为 **0**，如果为 **0** 就会释放 `page` ，因为 `mmap` 映射的时候并不会**页面结构(pgae)的引用计数**，内核并不知道是否取消了内存的映射。所以就会出现映射未取消就释放 `page` 的情况，而导致用户虚拟地址对物理地址映射未取消的 `UAF` 。

![image-20250320154540206](./assets/image-20250320154540206.png)

#### 4.CVE-2021-1732

**Test version**: Windows 10 17763

**Vulnerability**: 漏洞核心不只是“未初始化内存”本身，而是 **win32k 的 KernelCallback 信任边界失效**：在创建窗口并分配 `WndExtra` 的流程中，内核会通过 `KeUserModeCallback` 调用用户态回调（如 `xxxClientAllocWindowClassExtraBytes`，函数指针来自 `PEB->KernelCallbackTable`），并将用户态 `NtCallbackReturn` 返回的数据写回内核对象字段。攻击者在回调窗口期内调用 `NtUserConsoleControl` 切换窗口的关键标志位（常见描述为 `0x800` 的 ConsoleWindow 相关语义），导致同一个字段（如 `tagWND` 中保存 `WndExtra` 的值）在后续被内核 **按“offset（相对 kernel desktop heap base 的偏移）”而非“pointer（用户态指针）”解释**。当攻击者再通过 `NtCallbackReturn` 返回可控数值时，就会出现 **字段值与解释语义不同步（out-of-sync）** 的类型/语义混淆，最终在 `kernel desktop heap` 相关地址计算中产生 **越界读写（OOB R/W）**。利用上通常先把相邻窗口对象的关键字段（如 `cbWndExtra`、`spmenu` 等）打坏/扩展读写范围，将 OOB 放大为稳定的 **任意读 + 任意写**，最后通过遍历 `EPROCESS->ActiveProcessLinks` 找到 PID 4 的 SYSTEM Token 并替换当前进程 Token，实现本地提权到 SYSTEM。

![image-20260120134227989](assets/image-20260120134227989.png)

#### 5.CVE-2021-40449

**Test version**: Windows 10 17763

**Vulnerability**: 漏洞核心不仅仅只是在于 `ResetDC` 本身，而是 **GDI 打印路径中的用户态驱动回调（UMPD callback）形成了信任边界缺口**：在 `ResetDC` 触发的 DC 重建过程中，内核需要依据新的 `DEVMODE` 重建 `DC / PDEV / SURFACE`，由于打印机驱动大量实现于用户态（UMPD），内核会通过 `PDEV->apfn[]` 的函数表回调到用户态驱动例程（典型如 `UMPDDrvResetPDEV`，以及创建流程中的 `DrvEnablePDEV` 等）。该回调发生在 **旧 DC 已清理、新 DC 尚未完全绑定/一致性未恢复** 的关键窗口期内；攻击者可通过伪造/劫持 `PDEV` 的回调函数指针或利用回调期间的对象状态不一致（例如提前释放、替换内部指针/句柄、破坏引用计数或结构字段），制造 **Use-After-Free / 对象混淆 / 任意函数指针调用** 等内核态异常控制流，进而获得稳定的读写原语。利用链中借助可控的大池块（`ThNm`）布置伪造结构(`RTL_BITMAP`)，然后调用 `RtlSetAllBits` 位图操作把目标内核地址范围写成全 1，从而将 `_TOKEN.Privileges`（`Present/Enabled`）置满以开启全部特权，最终配合 token 操作/进程句柄能力完成本地提权到 SYSTEM。

![image-20260203143928274](assets/image-20260203143928274.png)
