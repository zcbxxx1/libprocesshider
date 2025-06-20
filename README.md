libprocesshider
================

使用 ld 预加载器在 Linux 下隐藏进程。

完整教程请访问 https://sysdigcloud.com/hiding-linux-processes-for-fun-and-profit/

简而言之，编译so文件：

```
gianluca@sid:~/libprocesshider$ make
gcc -Wall -fPIC -shared -o libprocesshider.so processhider.c -ldl
gianluca@sid:~/libprocesshider$ sudo mv libprocesshider.so /usr/local/lib/
```
或者指定SONAME

```
gianluca@sid:~/libprocesshider$ make LIB=libfakeproc.so
gcc -Wall -fPIC -shared -o libfakeproc.so processhider.c -ldl
gianluca@sid:~/libprocesshider$ sudo mv libfakeproc.so /usr/local/lib/
```

使用全局动态链接器加载

```
root@sid:~# echo /usr/local/lib/libprocesshider.so >> /etc/ld.so.preload
```

这样你的进程就隐藏了

```
gianluca@sid:~$ sudo ps aux
USER PID %CPU %MEM VSZ RSS TTY STAT START TIME命令
...

gianluca@sid:~$ sudo lsof -ni
命令 PID 用户 FD 类型 设备大小/关闭 节点名称
...
```
