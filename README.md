Kernel学习的一些例题
相关知识点和题解都在先知论坛：[默文 的个人主页 - 先知社区](https://xz.aliyun.com/users/154057/news)



## Catalog

1. CVE-2022-2602
1. CVE-2023-2598

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
