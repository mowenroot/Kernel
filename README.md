Kernel学习的一些例题
相关知识点和题解都在先知论坛：https://xz.aliyun.com/u/94502



## Catalog

1. CVE-2022-2602



------

## Detail

#### 1. CVE-2022-2602

[writeup](#) 

**Test version**: Linux-5.18.19

**Protection**: 开启KASLR/SMEP/SMAP。

**Vulnerability**: 漏洞本质是 `filp` 的 `UAF` 。 `io_uring` 模块提供的 `io_uring_register` 系统调用中的 `IORING_REGISTER_FILES` 能注册文件。调用后会把**文件**放入 `io_uring->sk->receive_queue` 。在 `Linux gc` 垃圾回收机制中又会将该列表的文件取出，尝试会将文件取出并**释放**。导致下次使用 `io_uring` 利用该文件时会触发 `UAF` 。由于UNIX_GC垃圾回收机制会错误释放 `io_uring` 中还在使用的文件结构体（正在往`"/tmp/mowen"`普通文件写入恶意数据），可以**采用DirtyCred方法**，打开大量`"/etc/passwd"`文件，覆盖刚刚释放的`file`结构体，这样最后就会实际往`"/etc/passwd"`文件写入恶意数据。

