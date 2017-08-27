# libaudit in Go

libaudit-go is a go package for interfacing with Linux audit.

[![Build Status](https://travis-ci.org/readhelper/libaudit-go.svg?branch=master)](https://travis-ci.org/readhelper/libaudit-go)
[![Go Report Card](https://goreportcard.com/badge/readhelper/libaudit-go "Go Report Card")](https://goreportcard.com/report/readhelper/libaudit-go)

libaudit-go is a pure Go client library for interfacing with the Linux auditing framework. It provides functions
to interact with the auditing subsystems over Netlink, including controlling the rule set and obtaining/interpreting
incoming audit events.

libaudit-go can be used to build go applications which perform tasks similar to the standard Linux auditing daemon
`auditd`.

To get started see package documentation at [godoc](https://godoc.org/github.com/mozilla/libaudit-go).

Some key functions are discussed in the overview section below.

## Overview

### General 

##### NewNetlinkConnection 

To use libaudit-go programs will need to initialize a new Netlink connection. `NewNetlinkConnection` can be used
to allocate a new `NetlinkConnection` type which can then be passed to other functions in the library.

```go
s, err := libaudit.NewNetlinkConnection()
if err != nil {
        fmt.Printf("NewNetlinkConnection: %v\n", err)
} 
defer s.Close()
```

`NetlinkConnection` provides a `Send` and `Receive` method to send and receive Netlink messages to the kernel,
however generally applications will use the various other functions included in libaudit-go and do not need to
call these functions directly.

##### GetAuditEvents

GetAuditEvents starts an audit event monitor in a go-routine and returns. Programs can call this function and
specify a callback function as an argument. When the audit event monitor receives a new event, this callback
function will be called with the parsed `AuditEvent` as an argument.

```go

func myCallback(msg *libaudit.AuditEvent, err error) {
        if err != nil {
            // An error occurred getting or parsing the audit event
            return
        }
	// Print the fields
        fmt.Println(msg.Data)
	// Print the raw event
        fmt.Println(msg.Raw)
}

libaudit.GetAuditEvents(s, myCallback)
```

##### GetRawAuditEvents

`GetRawAuditEvents` behaves in a similar manner to `GetAuditEvents`, however programs can use this function
to instead just retrieve raw audit events from the kernel as a string, instead of having libaudit-go parse
these audit events into an `AuditEvent` type.

### Audit Rules

Audit rules can be loaded into the kernel using libaudit-go, however the format differs from the common rule
set used by userspace tools such as auditctl/auditd.

libaudit-go rulesets are defined as a JSON document. See [rules.json](./testdata/rules.json) as an example.
The libaudit-go type which stores the rule set is `AuditRules`.

##### SetRules

`SetRules` can be used to load an audit rule set into the kernel. The function takes a marshalled `AuditRules`
type as an argument (slice of bytes), and converts the JSON based rule set into a set of audit rules suitable
for submission to the kernel.

The function then makes the required Netlink calls to clear the existing rule set and load the new rules.

```go
// Load all rules from a file
content, err := ioutil.ReadFile("audit.rules.json")
if err != nil {
        fmt.Printf("error: %v\n", err)
	os.Exit(1)
}

// Set audit rules
err = libaudit.SetRules(s, content)
if err != nil {
        fmt.Printf("error: %v\n", err)
        os.Exit(1)
}
```

audit命令
auditctl audit系统管理工具，用来获取状态，增加删除监控规则。
ausearch 查询audit log工具
aureport 输出audit系统报告


auditctl示例
auditctl -w /etc/passwd -p war -k password_file
auditctl -w /tmp -p e -k webserver_watch_tmp
-w 监控文件路径 /etc/passwd, 
-p 监控文件筛选 r(读) w(写) x(执行) a(属性改变)
-k 筛选字符串，用于查询监控日志
auditctl -a exit,never -S mount
auditctl -a entry,always -S all -F pid=1005
-S 监控系统调用
-F 给出更多监控条件(pid/path/egid/euid等)


25.2  编写审计规则与观察器 
Linux Auditing System可以用来为事件写规则，比如系统调用，比如用auditctl命令行实用程序观察文件或目录上的操作。如果用初始化脚本启动auditd(用 service auditd start命令)，则规则和观察器可以添加到/etc/audit/audit.rules中，以便在启动守护进程时执行它们。只有根用户可以读或修改这个文件。 
/etc/audit.audit.rules中的每个规则和观察器必须单独在一行中，以#开头的行会被忽略。规则和观察器是auditctl命令行选项，前面没有auditctl命令。它们从上到下阅读文件。如果一个或多个规则或观察器互相冲突，则使用找到的第一个。 
25.2.1  编写审计规则 
要添加审计规则，可在/etc/audit/audit.rules文件中用下面的语法： 
     -a <list>,<action> <options> 
警告： 
如果在运行守护进程时添加规则/etc/audit/audit.rules，则一定要以根用户身份用service auditd restart命令启用修改。也可以使用service auditd reload命令，但是这种方法不会提供配置文件错误的消息。 
列表名必须是下列名称之一。 
     task 
每个任务的列表。只有当创建任务时才使用。只有在创建时就已知的字段(比如UID)才可以用在这个列表中。 
     entry 
系统调用条目列表。当进入系统调用确定是否应创建审计时使用。 
     exit 
系统调用退出列表。当退出系统调用以确定是否应创建审计时使用。 
     user 
用户消息过滤器列表。内核在将用户空间事件传递给审计守护进程之前使用这个列表过滤用户空间事件。有效的字段只有uid、auid、gid和pid。 
     exclude 
事件类型排除过滤器列表。用于过滤管理员不想看到的事件。用msgtype字段指定您不想记录到日志中的消息。 
这个动作必须下面的动作之一： 
     never 
不生成审计记录。 
     always 
分配审计上下文，总是把它填充在系统调用条目中，总是在系统调用退出时写一个审计记录。 
<options>可以包括下面几个选项中的一个或多个。 
     -s <syscall> 
根据名称或数字指定一个系统。要指定所有系统调用，可使用all作为系统调用名称。如果程序使用了这个系统调用，则开始一个审计记录。可以为相同的规则指定多个系统调用，每个系统调用必须用-S启动。在相同的规则中指定多个系统，而不是列出单独的规则，这样可以导致更好的性能，因为只需要评价一个规则。 
     - F <name[=,!=,<,>,<=]value> 
指定一个规则字段。如果为一个规则指定了多个字段，则只有所有字段都为真才能启动一个审计记录。每个规则都必须用-F启动，最多可以指定64个规则。如果用用户名和组名作为字段，而不是用UID和GID，则会将它们解析为UID和GID以进行匹配。下面是有效的字段名： 
         pid 
进程ID。 
         ppid 
父进程的进程ID。 
         uid 
用户ID。 
         euid 
有效用户ID。 
         suid 
设置用户ID。 
         fsuid 
文件系统用户ID。 
         gid 
组ID。 
         egid 
有效组ID。 
         sgid 
设置组ID。 
         fsgid 
文件系统组ID。 
         auid 
审计ID，或者用户登录时使用的原始ID。 
         msgtype 
消息类型号。只应用在排除过滤器列表上。 
         pers 
OS Personality Number。 
         arch 
系统调用的处理器体系结构。指定精确的体系结构，比如i686(可以通过uname -m命令检索)或者指定b32来使用32位系统调用表，或指定b64来使用64位系统调用表。 
         devmajor 
Device Major Number。 
         devminor 
Device Minor Number。 
         inode 
Inode Number。 
         exit 
从系统调用中退出值。 
         success 
系统调用的成功值。1表是真/是，0表示假/否。 
         a0，a1，a2，a3 
分别表示系统调用的前4个参数。只能用数字值。 
         key 
设置用来标记事件的审计日志事件消息的过滤键。参见程序清单25-2和程序清单25-3中的示例。当添加观察器时，类似于使用-k选项。参见“编写审计规则与观察器”了解关于-k选项的详细信息。 
         obj_user 
资源的SELinux用户。 
         obj_role 
资源的SELinux角色。 
         obj_type 
资源的SELinux类型。 
         obj_lev_low 
资源的SELinux低级别。 
         obj_lev_high 
资源的SELinux高级别。 
         subj_role 
程序的SELinux角色。 
         subj_type 
程序的SELinux类型。 
         subj_sen 
程序的SELinux敏感性。 
         subj_clr 
程序的SELinux安全级别(clearance)。 
-a选项向列表末尾添加规则。要向列表开头添加规则，可用-A替换-a。删除语法相同的规则，用-d替换-a。要删除所有规则，可指定-D选项。程序清单25-2含有一些示例审计规则，比如/etc/audit/audit.rules。 
程序清单25-2  示例审计规则 
     #Record all file opens from user 501 
     #Use with caution since this can quickly 
     #produce a large quantity of records 
     -a exit,always -S open -F uid=501 -F key=501open 
     #Record file permission changes 
     -a entry,always -S chmod 
提示： 
如果安装了audit程序包，则其他示例在/usr/share/doc/audit-<version>/目录的*.rules文件中。 
当发生了定义的规则中的动作时，如果有一个规则在/etc/audit/auditd.conf中定义则它会通过调度程序发送，然后会有一条日志消息写到/var/log/audit/audit.log中。例如，程序清单25-3中含有程序清单25-2中的第一个规则的日志项，日志文件从用户501 打开。这个规则包括一个过滤键，它出现在程序清单25-3中日志项的末尾。 
程序清单25-3  示例审计规则日志消息 
     type=SYSCALL msg=audit(1168206647.422:5227): arch=c000003e syscall=2 
     success=no exit=-2 a0=7fff37fc5a40 a1=0 a2=2aaaaaaab000 a3=0 items=1 
     ppid=26640 pid=2716 auid=501 uid=501 gid=501 euid=501 suid=501 fsuid=501 
     egid=501 sgid=501 fsgid=501 tty=pts5 comm="vim" exe="/usr/bin/vim" 
     key="501open" 

日志查询
设置了监控后，会在/var/log/audit/audit.log里出现日志。
可以用此命令查看日志：
ausearch -f /etc/passwd -x rm
-k  利用auditctl指定的key查询
-x  执行程序
# ausearch -ts today -k password-file
# ausearch -ts 3/12/07 -k password-file
-ts 指定时间后的log (start time)
-te 指定时间前的log (end time)
