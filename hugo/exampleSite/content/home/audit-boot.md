유저 UID 를 통한 확인 방법

```bash
# ausearch -ui $UID --interpret
----
type=DAEMON_START msg=audit(2022년 09월 28일 01:42:53.647:2054) : op=start ver=3.0.7 format=enriched kernel=4.18.0-394.el8.x86_64 auid=unset pid=1014 uid=root ses=unset subj=system_u:system_r:auditd_t:s0 res=success 
----
type=SERVICE_START msg=audit(2022년 09월 28일 01:42:53.666:5) : pid=1 uid=root auid=unset ses=unset subj=system_u:system_r:init_t:s0 msg='unit=rpcbind comm=systemd exe=/usr/lib/systemd/systemd hostname=? addr=? terminal=? res=success' 
----
type=PROCTITLE msg=audit(2022년 09월 28일 01:42:53.714:6) : proctitle=/sbin/auditctl -R /etc/audit/audit.rules 
type=SYSCALL msg=audit(2022년 09월 28일 01:42:53.714:6) : arch=x86_64 syscall=sendto success=yes exit=60 a0=0x3 a1=0x7ffde2d79a90 a2=0x3c a3=0x0 items=0 ppid=1019 pid=1033 auid=unset uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=unset comm=auditctl exe=/usr/sbin/auditctl subj=system_u:system_r:unconfined_service_t:s0 key=(null) 
type=CONFIG_CHANGE msg=audit(2022년 09월 28일 01:42:53.714:6) : op=set audit_backlog_limit=8192 old=64 auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 res=yes 
----
type=PROCTITLE msg=audit(2022년 09월 28일 01:42:53.731:7) : proctitle=/sbin/auditctl -R /etc/audit/audit.rules 
type=SYSCALL msg=audit(2022년 09월 28일 01:42:53.731:7) : arch=x86_64 syscall=sendto success=yes exit=60 a0=0x3 a1=0x7ffde2d79a90 a2=0x3c a3=0x0 items=0 ppid=1019 pid=1033 auid=unset uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=unset comm=auditctl exe=/usr/sbin/auditctl subj=system_u:system_r:unconfined_service_t:s0 key=(null) 
type=CONFIG_CHANGE msg=audit(2022년 09월 28일 01:42:53.731:7) : op=set audit_failure=1 old=1 auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 res=yes 
----
type=PROCTITLE msg=audit(2022년 09월 28일 01:42:53.734:8) : proctitle=/sbin/auditctl -R /etc/audit/audit.rules 
type=SYSCALL msg=audit(2022년 09월 28일 01:42:53.734:8) : arch=x86_64 syscall=sendto success=yes exit=60 a0=0x3 a1=0x7ffde2d79a90 a2=0x3c a3=0x0 items=0 ppid=1019 pid=1033 auid=unset uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=unset comm=auditctl exe=/usr/sbin/auditctl subj=system_u:system_r:unconfined_service_t:s0 key=(null) 
type=CONFIG_CHANGE msg=audit(2022년 09월 28일 01:42:53.734:8) : op=set audit_backlog_wait_time=60000 old=60000 auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 res=yes 
----
type=SERVICE_START msg=audit(2022년 09월 28일 01:42:53.755:9) : pid=1 uid=root auid=unset ses=unset subj=system_u:system_r:init_t:s0 msg='unit=auditd comm=systemd exe=/usr/lib/systemd/systemd hostname=? addr=? terminal=? res=success' 
----
type=SYSTEM_BOOT msg=audit(2022년 09월 28일 01:42:53.767:10) : pid=1040 uid=root auid=unset ses=unset subj=system_u:system_r:init_t:s0 msg=' comm=systemd-update-utmp exe=/usr/lib/systemd/systemd-update-utmp hostname=? addr=? terminal=? res=success' 
----
type=SERVICE_START msg=audit(2022년 09월 28일 01:42:53.771:11) : pid=1 uid=root auid=unset ses=unset subj=system_u:system_r:init_t:s0 msg='unit=systemd-update-utmp comm=systemd exe=/usr/lib/systemd/systemd hostname=? addr=? terminal=? res=success' 
----
type=SERVICE_START msg=audit(2022년 09월 28일 01:42:54.173:12) : pid=1 uid=root auid=unset ses=unset subj=system_u:system_r:init_t:s0 msg='unit=ldconfig comm=systemd exe=/usr/lib/systemd/systemd hostname=? addr=? terminal=? res=success' 
----
type=SERVICE_START msg=audit(2022년 09월 28일 01:42:54.205:13) : pid=1 uid=root auid=unset ses=unset subj=system_u:system_r:init_t:s0 msg='unit=systemd-update-done comm=systemd exe=/usr/lib/systemd/systemd hostname=? addr=? terminal=? res=success' 
----
type=SERVICE_START msg=audit(2022년 09월 28일 01:42:54.216:14) : pid=1 uid=root auid=unset ses=unset subj=system_u:system_r:init_t:s0 msg='unit=irqbalance comm=systemd exe=/usr/lib/systemd/systemd hostname=? addr=? terminal=? res=success' 
----
type=PROCTITLE msg=audit(2022년 09월 28일 01:42:56.750:76) : proctitle=/usr/sbin/ebtables-restore --noflush 
type=SYSCALL msg=audit(2022년 09월 28일 01:42:56.750:76) : arch=x86_64 syscall=sendmsg success=yes exit=884 a0=0x3 a1=0x7ffec5f3a630 a2=0x0 a3=0x7ffec5f3a61c items=0 ppid=1157 pid=1518 auid=unset uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=unset comm=ebtables-restor exe=/usr/sbin/xtables-nft-multi subj=system_u:system_r:iptables_t:s0 key=(null) 
type=NETFILTER_CFG msg=audit(2022년 09월 28일 01:42:56.750:76) : table=nat:29 family=bridge entries=3 op=nft_register_chain pid=1518 subj=system_u:system_r:iptables_t:s0 comm=ebtables-restor 
type=NETFILTER_CFG msg=audit(2022년 09월 28일 01:42:56.750:76) : table=filter:29 family=bridge entries=3 op=nft_register_chain pid=1518 subj=system_u:system_r:iptables_t:s0 comm=ebtables-restor 
----
type=PROCTITLE msg=audit(2022년 09월 28일 01:42:56.755:77) : proctitle=/usr/libexec/platform-python -s /usr/sbin/firewalld --nofork --nopid 
type=SYSCALL msg=audit(2022년 09월 28일 01:42:56.755:77) : arch=x86_64 syscall=sendmsg success=yes exit=172 a0=0x6 a1=0x7ffc55c4ce60 a2=0x0 a3=0x7ffc55c4bdac items=0 ppid=1 pid=1157 auid=unset uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=unset comm=firewalld exe=/usr/libexec/platform-python3.6 subj=system_u:system_r:firewalld_t:s0 key=(null) 
type=NETFILTER_CFG msg=audit(2022년 09월 28일 01:42:56.755:77) : table=firewalld:30 family=inet entries=1 op=nft_register_table pid=1157 subj=system_u:system_r:firewalld_t:s0 comm=firewalld 
type=NETFILTER_CFG msg=audit(2022년 09월 28일 01:42:56.755:77) : table=firewalld:30 family=ipv4 entries=1 op=nft_register_table pid=1157 subj=system_u:system_r:firewalld_t:s0 comm=firewalld 
type=NETFILTER_CFG msg=audit(2022년 09월 28일 01:42:56.755:77) : table=firewalld:30 family=ipv6 entries=1 op=nft_register_table pid=1157 subj=system_u:system_r:firewalld_t:s0 comm=firewalld 
----
type=PROCTITLE msg=audit(2022년 09월 28일 01:42:56.798:79) : proctitle=/usr/libexec/platform-python -s /usr/sbin/firewalld --nofork --nopid 
type=SYSCALL msg=audit(2022년 09월 28일 01:42:56.798:79) : arch=x86_64 syscall=sendmsg success=yes exit=32792 a0=0x6 a1=0x7ffc55c4ce60 a2=0x0 a3=0x7ffc55c4bdac items=0 ppid=1 pid=1157 auid=unset uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=unset comm=firewalld exe=/usr/libexec/platform-python3.6 subj=system_u:system_r:firewalld_t:s0 key=(null) 
type=NETFILTER_CFG msg=audit(2022년 09월 28일 01:42:56.798:79) : table=firewalld:31 family=inet entries=199 op=nft_register_chain pid=1157 subj=system_u:system_r:firewalld_t:s0 comm=firewalld 
type=NETFILTER_CFG msg=audit(2022년 09월 28일 01:42:56.798:79) : table=firewalld:31 family=ipv4 entries=54 op=nft_register_chain pid=1157 subj=system_u:system_r:firewalld_t:s0 comm=firewalld 
type=NETFILTER_CFG msg=audit(2022년 09월 28일 01:42:56.798:79) : table=firewalld:31 family=ipv6 entries=54 op=nft_register_chain pid=1157 subj=system_u:system_r:firewalld_t:s0 comm=firewalld 
----
type=SERVICE_START msg=audit(2022년 09월 28일 01:42:56.871:78) : pid=1 uid=root auid=unset ses=unset subj=system_u:system_r:init_t:s0 msg='unit=libvirtd comm=systemd exe=/usr/lib/systemd/systemd hostname=? addr=? terminal=? res=success' 
----
type=PROCTITLE msg=audit(2022년 09월 28일 01:42:57.255:80) : proctitle=/usr/sbin/iptables -w --table filter --new-chain LIBVIRT_INP 
type=SYSCALL msg=audit(2022년 09월 28일 01:42:57.255:80) : arch=x86_64 syscall=sendmsg success=yes exit=128 a0=0x3 a1=0x7fffa8301bc0 a2=0x0 a3=0x7fffa8301bac items=0 ppid=1376 pid=1806 auid=unset uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=unset comm=iptables exe=/usr/sbin/xtables-nft-multi subj=system_u:system_r:iptables_t:s0-s0:c0.c1023 key=(null) 
type=NETFILTER_CFG msg=audit(2022년 09월 28일 01:42:57.255:80) : table=filter:35 family=ipv4 entries=1 op=nft_register_chain pid=1806 subj=system_u:system_r:iptables_t:s0-s0:c0.c1023 comm=iptables 
----
type=PROCTITLE msg=audit(2022년 09월 28일 02:01:28.674:193) : proctitle=/usr/libexec/platform-python -s /usr/sbin/firewalld --nofork --nopid 
type=SYSCALL msg=audit(2022년 09월 28일 02:01:28.674:193) : arch=x86_64 syscall=sendmsg success=yes exit=1880 a0=0x6 a1=0x7ffc55c4c400 a2=0x0 a3=0x7ffc55c4b34c items=0 ppid=1 pid=1157 auid=unset uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=unset comm=firewalld exe=/usr/libexec/platform-python3.6 subj=system_u:system_r:firewalld_t:s0 key=(null) 
type=NETFILTER_CFG msg=audit(2022년 09월 28일 02:01:28.674:193) : table=firewalld:86 family=inet entries=4 op=nft_register_rule pid=1157 subj=system_u:system_r:firewalld_t:s0 comm=firewalld 
type=NETFILTER_CFG msg=audit(2022년 09월 28일 02:01:28.674:193) : table=firewalld:86 family=ipv4 entries=2 op=nft_register_rule pid=1157 subj=system_u:system_r:firewalld_t:s0 comm=firewalld 
type=NETFILTER_CFG msg=audit(2022년 09월 28일 02:01:28.674:193) : table=firewalld:86 family=ipv6 entries=2 op=nft_register_rule pid=1157 subj=system_u:system_r:firewalld_t:s0 comm=firewalld 
----
type=SYSTEM_RUNLEVEL msg=audit(2022년 09월 28일 02:57:59.212:146) : pid=2373 uid=root auid=unset ses=unset subj=system_u:system_r:init_t:s0 msg='old-level=N new-level=5 comm=systemd-update-utmp exe=/usr/lib/systemd/systemd-update-utmp hostname=? addr=? terminal=? res=success' 
----
type=SERVICE_START msg=audit(2022년 09월 28일 02:57:59.214:147) : pid=1 uid=root auid=unset ses=unset subj=system_u:system_r:init_t:s0 msg='unit=systemd-update-utmp-runlevel comm=systemd exe=/usr/lib/systemd/systemd hostname=? addr=? terminal=? res=success' 
----
type=SERVICE_STOP msg=audit(2022년 09월 28일 02:57:59.214:148) : pid=1 uid=root auid=unset ses=unset subj=system_u:system_r:init_t:s0 msg='unit=systemd-update-utmp-runlevel comm=systemd exe=/usr/lib/systemd/systemd hostname=? addr=? terminal=? res=success' 
----
type=USER_AUTH msg=audit(2022년 09월 28일 02:58:04.001:149) : pid=2375 uid=root auid=unset ses=unset subj=system_u:system_r:xdm_t:s0-s0:c0.c1023 msg='op=PAM:authentication grantors=pam_usertype,pam_localuser,pam_unix,pam_gnome_keyring acct=ahnlab exe=/usr/libexec/gdm-session-worker hostname=localhost.localdomain addr=? terminal=/dev/tty1 res=success' 
----
type=USER_ACCT msg=audit(2022년 09월 28일 02:58:04.006:150) : pid=2375 uid=root auid=unset ses=unset subj=system_u:system_r:xdm_t:s0-s0:c0.c1023 msg='op=PAM:accounting grantors=pam_unix,pam_localuser acct=ahnlab exe=/usr/libexec/gdm-session-worker hostname=localhost.localdomain addr=? terminal=/dev/tty1 res=success' 
----
type=CRED_ACQ msg=audit(2022년 09월 28일 02:58:04.011:151) : pid=2375 uid=root auid=unset ses=unset subj=system_u:system_r:xdm_t:s0-s0:c0.c1023 msg='op=PAM:setcred grantors=pam_localuser,pam_unix,pam_gnome_keyring acct=ahnlab exe=/usr/libexec/gdm-session-worker hostname=localhost.localdomain addr=? terminal=/dev/tty1 res=success' 
----
type=LOGIN msg=audit(2022년 09월 28일 02:58:04.018:152) : pid=2375 uid=root subj=system_u:system_r:xdm_t:s0-s0:c0.c1023 old-auid=unset auid=ahnlab tty=(none) old-ses=4294967295 ses=2 res=yes 
----
type=PROCTITLE msg=audit(2022년 09월 28일 02:58:04.018:152) : proctitle=gdm-session-worker [pam/gdm-password] 
type=SYSCALL msg=audit(2022년 09월 28일 02:58:04.018:152) : arch=x86_64 syscall=write success=yes exit=4 a0=0xa a1=0x7ffe1f2a26c0 a2=0x4 a3=0x0 items=0 ppid=1238 pid=2375 auid=ahnlab uid=root gid=ahnlab euid=root suid=root fsuid=root egid=ahnlab sgid=ahnlab fsgid=ahnlab tty=(none) ses=2 comm=gdm-session-wor exe=/usr/libexec/gdm-session-worker subj=system_u:system_r:xdm_t:s0-s0:c0.c1023 key=(null) 
----
type=USER_ROLE_CHANGE msg=audit(2022년 09월 28일 02:58:04.031:153) : pid=2375 uid=root auid=ahnlab ses=2 subj=system_u:system_r:xdm_t:s0-s0:c0.c1023 msg='pam: default-context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 selected-context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 exe=/usr/libexec/gdm-session-worker hostname=localhost.localdomain addr=? terminal=/dev/tty2 res=success' 
----
type=SERVICE_START msg=audit(2022년 09월 28일 02:58:04.063:154) : pid=1 uid=root auid=unset ses=unset subj=system_u:system_r:init_t:s0 msg='unit=user-runtime-dir@1000 comm=systemd exe=/usr/lib/systemd/systemd hostname=? addr=? terminal=? res=success' 
----
type=USER_ACCT msg=audit(2022년 09월 28일 02:58:04.084:155) : pid=2387 uid=root auid=unset ses=unset subj=system_u:system_r:init_t:s0 msg='op=PAM:accounting grantors=pam_unix acct=ahnlab exe=/usr/lib/systemd/systemd hostname=? addr=? terminal=? res=success' 
----
type=USER_ROLE_CHANGE msg=audit(2022년 09월 28일 02:58:04.084:156) : pid=2387 uid=root auid=unset ses=unset subj=system_u:system_r:init_t:s0 msg='pam: default-context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 selected-context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 exe=/usr/lib/systemd/systemd hostname=? addr=? terminal=? res=success' 
----
type=USER_LOGIN msg=audit(2022년 09월 28일 05:35:46.992:299) : pid=7789 uid=root auid=ahnlab ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=login id=ahnlab exe=/usr/sbin/sshd hostname=? addr=192.168.66.1 terminal=ssh res=success' 
----
type=USER_START msg=audit(2022년 09월 28일 05:35:46.992:300) : pid=7789 uid=root auid=ahnlab ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=login id=ahnlab exe=/usr/sbin/sshd hostname=? addr=192.168.66.1 terminal=ssh res=success' 
----
type=CRYPTO_KEY_USER msg=audit(2022년 09월 28일 05:35:47.006:301) : pid=7789 uid=root auid=ahnlab ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=destroy kind=server fp=SHA256:3b:04:1b:5b:09:fb:ec:42:8b:65:f7:08:59:1f:6d:40:16:2a:c1:71:2b:4d:e8:5f:c1:bf:4e:ae:6b:b3:af:a8 direction=? spid=7797 suid=ahnlab  exe=/usr/sbin/sshd hostname=? addr=? terminal=? res=success' 
----
type=CRYPTO_KEY_USER msg=audit(2022년 09월 28일 05:35:47.334:302) : pid=7789 uid=root auid=ahnlab ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=destroy kind=session fp=? direction=both spid=7794 suid=ahnlab rport=54041 laddr=192.168.66.130 lport=22  exe=/usr/sbin/sshd hostname=? addr=192.168.66.1 terminal=? res=success' 
----
type=CRYPTO_KEY_USER msg=audit(2022년 09월 28일 05:35:47.339:303) : pid=7789 uid=root auid=ahnlab ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=destroy kind=server fp=SHA256:3b:04:1b:5b:09:fb:ec:42:8b:65:f7:08:59:1f:6d:40:16:2a:c1:71:2b:4d:e8:5f:c1:bf:4e:ae:6b:b3:af:a8 direction=? spid=7794 suid=ahnlab  exe=/usr/sbin/sshd hostname=? addr=? terminal=? res=success' 
----
type=USER_END msg=audit(2022년 09월 28일 05:35:47.351:304) : pid=7789 uid=root auid=ahnlab ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=PAM:session_close grantors=pam_selinux,pam_loginuid,pam_selinux,pam_namespace,pam_keyinit,pam_keyinit,pam_limits,pam_systemd,pam_unix,pam_umask,pam_lastlog acct=ahnlab exe=/usr/sbin/sshd hostname=192.168.66.1 addr=192.168.66.1 terminal=ssh res=success' 
----
type=CRED_DISP msg=audit(2022년 09월 28일 05:35:47.352:305) : pid=7789 uid=root auid=ahnlab ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=PAM:setcred grantors=pam_localuser,pam_unix acct=ahnlab exe=/usr/sbin/sshd hostname=192.168.66.1 addr=192.168.66.1 terminal=ssh res=success' 
----
type=USER_END msg=audit(2022년 09월 28일 05:35:47.358:306) : pid=7789 uid=root auid=ahnlab ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=login id=ahnlab exe=/usr/sbin/sshd hostname=? addr=192.168.66.1 terminal=ssh res=success' 
----
type=USER_LOGOUT msg=audit(2022년 09월 28일 05:35:47.359:307) : pid=7789 uid=root auid=ahnlab ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=login id=ahnlab exe=/usr/sbin/sshd hostname=? addr=192.168.66.1 terminal=ssh res=success' 
```