+++
weight = 10
+++

## Index

- 1. audit 을 어떻게 활용할까?
    - 1.1 큰 그림
    - 1.2 man
    - 1.3 audit 슈퍼 유저가 되기

- 2. 리눅스 커널 audit 내부 구조 분석!
    - 2.1. 언제 어떻게 초기화 되는가?
    - 2.2. **audit.log** 로그에 찍히기까지
    - 2.3. **audit rule** 을 어떻게 로드할까?

- 3. 참고

---

### 1. audit 을 어떻게 활용할까? 🤔

- 🤔 어떻게 증거(로그)를 남기면 좋을까요?
  - 스토리지 서버 *`/opt` 디렉토리 안에 중요한 파일을 누가 지우셨어욥!?*
  - 컨테이너 안에 *이상한 소프트웨어가 자꾸 설치되요. 누가 설치한거죠..?*
  - 사내 *소스 서버에 자꾸 이상한 IP 가 접근합니다. 이러다가 전부 DRM 걸리거나 소스 콸콸콸 유출 아니겠죠?!*

#### 고민하지 말고, audit 을 사용해봅시다!

---

### 1. audit 을 어떻게 활용할까? 🤔

- **audit 을 잘 사용하기 위한 사용법, 그리고 커널/유저 동작과 소프트웨어 컴포넌트는 어떻게 구성되어 있는지 살펴봅니다.**

<img src="000-audit-logging.png" alt="audit_components" width="600">

---

### 1.1 큰 그림

- 유저 프로세스가 하는 행동의 로그를 남기기 위한 커널 프로세스 kaudit 와 유저 libaudit 프레임워크를 활용한 소프트웨어 인프라입니다.

<img src="000-audit_components.png" alt="audit_components" width="600">

- 커널 스페이스의 audit lsm hook 로 ctx -> audit_context -> skb
- netlink 로 auditd 와 통신하며 행동 로깅 및 새로운 룰을 적용합니다.

---

### 1.1 주요 특징

- 커널 프로세스로 상주 중인 kaudit 은 **security/lsm_audit.c** Hook 을 사용하여 ctx 정보를 가져옵니다.
- auditd 가 올라오면서 **audit.rules** 파일을 읽어 정책을 적용합니다.
- auditctl 로 운영 중인 시스템에 적용합니다.
- 아키텍쳐 지원 : arm, x86, s390 (32, 64 bit)
  - [aarch64_table.h](https://github.com/linux-audit/audit-userspace/blob/v3.0.9/lib/aarch64_table.h)
- 리눅스 커널 시스템 콜 테이블의 새로운 시스템 콜을 팔로우 업 합니다.
    - (예) `_S(280, "bpf")` audit 3.0 BPF 시스템 콜 감사 정책 지원
    - Add [bpf syscall](https://man7.org/linux/man-pages/man2/bpf.2.html) command argument interpretation to auparse
    - 호스트 머신에서 virtual machine, container 감시 관련 feature 를 확장 중입니다.
- audit 은 빨간 모자의 안보가 중요한 서버 솔루션에서 [침입 탐지 시스템(Intrusion Detection System)](https://ko.wikipedia.org/wiki/침입_탐지_시스템)으로 활용 중입니다.

---

### 1.2 man

- auditd 는 유저 공간 Linux Auditing System 입니다.
  - audit records를 디스크에 쓰는 임무를 맡은 친구죠.
- 로그는 ausearch 또는 aureport 를 통하여 편리하게 볼 수 있습니다.
- auditctl 을 통해 운영 중에 audit 설정을 바꾸거나 룰을 변경할 수 있어요!
- augenrules 은 /etc/audit/rules.d/ 안에 있는 룰 파일들을 */etc/audit/audit.rules* 파일로 만들어 줍니다.
- auditd.conf 설정을 바꾸어서 auditd 를 입맛대로 설정할 수 있어요!

---

### 1.3 audit 슈퍼 유저가 되기 - 실행 확인하기

```bash
# service auditd status
Redirecting to /bin/systemctl status auditd.service
● auditd.service - Security Auditing Service
   Loaded: loaded (/usr/lib/systemd/system/auditd.service; enabled; vendor preset: enabled)
   Active: active (running) since Wed 2022-09-28 01:42:53 KST; 54min ago
     Docs: man:auditd(8)
           https://github.com/linux-audit/audit-documentation
 Main PID: 1014 (auditd)
    Tasks: 4 (limit: 49134)
   Memory: 3.6M
   CGroup: /system.slice/auditd.service
           ├─1014 /sbin/auditd
           └─1016 /usr/sbin/sedispatch

 9월 28 01:42:53 localhost.localdomain augenrules[1033]: enabled 1
 9월 28 01:42:53 localhost.localdomain augenrules[1033]: failure 1
 9월 28 01:42:53 localhost.localdomain augenrules[1033]: pid 1014
 9월 28 01:42:53 localhost.localdomain augenrules[1033]: rate_limit 0
 9월 28 01:42:53 localhost.localdomain augenrules[1033]: backlog_limit 8192
 9월 28 01:42:53 localhost.localdomain augenrules[1033]: lost 0
 9월 28 01:42:53 localhost.localdomain augenrules[1033]: backlog 4
 9월 28 01:42:53 localhost.localdomain augenrules[1033]: backlog_wait_time 60000
 9월 28 01:42:53 localhost.localdomain augenrules[1033]: backlog_wait_time_actual 0
 9월 28 01:42:53 localhost.localdomain systemd[1]: Started Security Auditing Service.
```

- 리눅스 커널의 kauditd
- 유저 스페이스의 레드햇/데비안 계열 배포판 auditd 로 활성화 되어있습니다.

---

### 1.3 audit 슈퍼 유저가 되기 - 실행 확인하기

```
# 레드햇 계열 # dnf install auditd
# 데비안 계열 # apt install auditd
```

---

### 1.3 audit 슈퍼 유저가 되기 - aureport

ssh 접근, 즉 sshd fork 하여 유저가 로그인하는 행위의 로그를 봐 볼까요!

```bash
#  aureport -l --failed

Login Report
============================================
# date time auid host term exe success event
============================================
1. 2022년 09월 28일 05:33:54 (unknown) 192.168.66.1 ssh /usr/sbin/sshd no 205
2. 2022년 09월 28일 05:33:54 (unknown) 192.168.66.1 ssh /usr/sbin/sshd no 216
3. 2022년 09월 28일 05:34:06 (unknown) 192.168.66.1 ssh /usr/sbin/sshd no 227
4. 2022년 09월 28일 05:35:44 ahnlab 192.168.66.1 ssh /usr/sbin/sshd no 268
5. 2022년 09월 28일 05:35:44 ahnlab 192.168.66.1 ssh /usr/sbin/sshd no 281
```

```bash
#  aureport -l --success

Login Report
============================================
# date time auid host term exe success event
============================================
1. 2022년 09월 28일 04:47:43 1000 ::1 /dev/pts/1 /usr/sbin/sshd yes 208
2. 2022년 09월 28일 05:35:38 1000 192.168.66.1 /dev/pts/1 /usr/sbin/sshd yes 245
3. 2022년 09월 28일 05:35:46 1000 192.168.66.1 ssh /usr/sbin/sshd yes 299
```

---

### 1.3 audit 슈퍼 유저가 되기 - file rule

- 외부에서 /etc/ssh/sshd_config 파일을 읽거나 수정하려는 모든 시도를 남겨볼까요? 
- 해당 rule 을 sshd_config 키로 기록해보죠!

```bash
 $ auditctl -w /etc/ssh/sshd_config -p warx -k sshd_config
```

```bash
 $ # ausearch -k sshd_config
----
time->Wed Sep 28 06:04:31 2022
type=SYSCALL msg=audit(1664312671.115:387): arch=c000003e syscall=44 success=yes exit=1088 a0=4 a1=7ffc4fcb9be0 a2=440 a3=0 items=0 ppid=7613 pid=52609 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="auditctl" exe="/usr/sbin/auditctl" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)
type=CONFIG_CHANGE msg=audit(1664312671.115:387): auid=1000 ses=3 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key="sshd_config" list=4 res=1
----
time->Wed Sep 28 06:04:46 2022
type=PATH msg=audit(1664312686.595:388): item=0 name="/etc/ssh/sshd_config" inode=103004708 dev=fd:00 mode=0100600 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:etc_t:s0 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=SYSCALL msg=audit(1664312686.595:388): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=55dbad3cf050 a2=0 a3=0 items=1 ppid=7613 pid=53627 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="vim" exe="/usr/bin/vim" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="sshd_config"
```

---

### 1.3 audit 슈퍼 유저가 되기 - record type

- type=SYSCALL
  - type 필드에는 레코드 유형이 포함됩니다. 이 예제에서 SYSCALL 값은 커널에 대한 시스템 호출에 의해 이 레코드가 트리거되었음을 지정합니다.
- key="sshd_config"
  - 키 필드는 감사 로그에서 이 이벤트를 생성한 규칙과 관련된 관리자 정의 문자열을 기록합니다.

```bash
type=SYSCALL msg=audit(1364481363.243:24287): arch=c000003e
syscall=2 success=no exit=-13 
a0=7fffd19c5592 a1=0 a2=7fffd19c4b50 a3=a items=1 
ppid=2686 pid=3538 auid=1000 
uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 
tty=pts0 ses=1 comm="cat" exe="/bin/cat" 
subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 
key="sshd_config"
```

---

### 1.3 audit 슈퍼 유저가 되기 - record type

- ppid=2686
  - ppid 필드는 상위 프로세스 ID(PPID)를 기록합니다. 이 경우 2686 은 bash 와 같은 상위 프로세스의 PPID였습니다.
- pid=3538
  - pid 필드는 프로세스 ID(PID)를 기록합니다. 이 경우 3538 은 cat 프로세스의 PID입니다.
- auid=1000
  - auid 필드는 loginuid인 Audit 사용자 ID를 기록합니다. 이 ID는 로그인 시 사용자에게 할당되며,
    예를 들어 su - john 명령으로 사용자 계정을 전환하여 사용자의 ID가 변경될 경우에도 모든 프로세스에 상속됩니다.

```bash
type=SYSCALL msg=audit(1364481363.243:24287): arch=c000003e
syscall=2 success=no exit=-13 a0=7fffd19c5592 a1=0 a2=7fffd19c4b50 a3=a items=1 
ppid=2686 pid=3538 auid=1000 uid=1000 gid=1000 euid=1000
suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 
tty=pts0 ses=1 comm="cat" exe="/bin/cat" 
subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="sshd_config"
```

---

### 1.3 audit 슈퍼 유저가 되기 - network rule

- 유입, 유출되는 네트워크 연결을 확인할 수 있습니다.
  - 172.20.14.41:60822 에서 현재 localhost 로 접근을 확인 가능합니다!

```bash
 $ auditctl -a always,exit -F arch=b64 -S accept,connect -F key=external-access
```

```bash
type=PROCTITLE msg=audit(2022년 08월 02일 09:47:19.345:372385) : 
proctitle=/usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf
type=SOCKADDR msg=audit(2022년 08월 02일 09:47:19.345:372385) : 
saddr={ fam=inet laddr=172.20.14.41 lport=60822 }
type=SYSCALL msg=audit(2022년 08월 02일 09:47:19.345:372385) : 
arch=x86_64 syscall=accept success=yes exit=11 
a0=0x4 a1=0x7fffffffe870 a2=0x7fffffffe844 a3=0x3e8 
items=0 ppid=1 pid=22267 auid=unset uid=lighttpd gid=lighttpd 
euid=lighttpd suid=lighttpd fsuid=lighttpd egid=lighttpd sgid=lighttpd 
fsgid=lighttpd tty=(none) ses=unset comm=lighttpd 
exe=/usr/sbin/lighttpd key=my_accept
```

---

### 1.3 audit 슈퍼 유저가 되기 - process rule

- 일반 사용자의 root로 권한 상승 시도를 확인해볼까요?

```bash
 $ auditctl -a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=10.2.5.b-elevated-privs-setuid
```

```bash
type=SYSCALL msg=audit(1659428449.377:378871): arch=c000003e
syscall=59 success=yes exit=0 a0=6f4f60 a1=6fa4b0 a2=822900 a3=7fffffffe260
items=2 ppid=14078 pid=15495 auid=1052 uid=1052 gid=1052
euid=0 suid=0 fsuid=0 egid=1052 sgid=1052 fsgid=1052
tty=pts8 ses=26782 comm="su" exe="/usr/bin/su"
key="10.2.5.b-elevated-privs-setuid" 
---
type=USER_AUTH msg=audit(1659428456.960:378872): pid=15495 uid=1052 auid=1052 ses=26782
msg='op=PAM:authentication grantors=pam_faillock,pam_unix acct="root" exe="/usr/bin/su" hostname=localhost.localdomain addr=? terminal=pts/8 res=success'
```

- 이외에도 시스템 룰 예시를 조금 더 살펴볼려면? **[30-stig.rules](https://github.com/linux-audit/audit-userspace/blob/v3.0.9/rules/30-stig.rules)** 참고!
  - Security Technical Implementation (STIG, 미국 국방성의 DISA 보안 구성 표준)에서 요구하는 조건을 충족할 수 있도록 구성된 Audit 규칙입니다. 

---

### 1.3 audit 슈퍼 유저가 되기 - config

기본 설정은 아래와 같이 확인 할 수 있습니다.
- event buffer 사이즈 8192
- burst of events 시에 60000 만큼 기다린다.

```
# cat /etc/audit/rules.d/audit.rules 
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 8192

## This determine how long to wait in burst of events
--backlog_wait_time 60000

## Set failure mode to syslog
-f 1
```

```
# cat /etc/audit/audit.rules
## This file is automatically generated from /etc/audit/rules.d
-D
-b 8192
-f 1
--backlog_wait_time 60000
```
