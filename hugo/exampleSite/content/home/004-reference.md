+++
weight = 40
+++

### TODO

```
Future roadmap (subject to change):
===================================
3.1
* Basic HIDS based on reactive audit component
* Multi-thread audisp-remote
* Add keywords for time: month-ago, this-hour, last-hour
* If searching user/group doesn't map to uid/gid, do translated string search
* In auditd, look into non-blocking handling of write to plugins
* Support multiple time streams when searching

3.2
* Container support
* Support TLS PSK as remote logging transport
* Add rule verify to detect mismatch between in-kernel and on-disk rules
* audisp-remote, add config to say what home network is so 
  laptops don't try if their not on a network that can reach the server.
* Fix audit.pc.in to use Requires.private
* Change ausearch to output name="" unless its a real null.
  (mount) ausearch-report.c, 523. FIXME
* Fix SIGHUP for auditd network settings
* Add ability to filter events in auditd
```

---

# 🤗

이상입니다. ^^7 고생하셨습니다!

---

### 참고

- [SLES 15-SP1 - Part VI The Linux Audit Framework](https://documentation.suse.com/sles/15-SP1/html/SLES-all/part-audit.html#)
- [Audit and IDS - Red Hat People](https://people.redhat.com/sgrubb/audit/audit-ids.pdf)
- [Tracking User and System activity with Oracle Linux Auditing](https://www.youtube.com/watch?v=w-XN9PGlMDc)
- [Stop disabling SELinux](https://stopdisablingselinux.com/)

### misc(audit package)

```
# rpm -ql audit
/etc/audit
/etc/audit/audit-stop.rules
/etc/audit/audit.rules
/etc/audit/auditd.conf
/etc/audit/plugins.d
/etc/audit/plugins.d/af_unix.conf
/etc/audit/rules.d
/etc/audit/rules.d/audit.rules
/usr/bin/aulast
/usr/bin/aulastlog
/usr/bin/ausyscall
/usr/bin/auvirt
/usr/lib/.build-id
/usr/lib/.build-id/0a
/usr/lib/.build-id/0a/54a2aeda2ce2f0cc9c789ab94afde974ea3ddf
/usr/lib/.build-id/15
/usr/lib/.build-id/15/be5ccbbd0ba37fea823d161d849a3d48671c64
/usr/lib/.build-id/2d
/usr/lib/.build-id/2d/733d5160c5a1ef08df0c709fb7436df2e3a548
/usr/lib/.build-id/3f
/usr/lib/.build-id/3f/bf084e6e5e599ac11ef7055de93519681e0d78
/usr/lib/.build-id/4a
/usr/lib/.build-id/4a/0842df3b270ee02070f848d05b8c6a456f7e64
/usr/lib/.build-id/4b
/usr/lib/.build-id/4b/f99725734e3834085ca9078cf97988a5d63ded
/usr/lib/.build-id/57
/usr/lib/.build-id/57/32c733d13c22aa5737b7ca085ec59191ef385e
/usr/lib/.build-id/cb
/usr/lib/.build-id/cb/4d2ae2ccacd7d5bcd9629242ab76b0e780988a
/usr/lib/.build-id/d7
/usr/lib/.build-id/d7/58719c24909e850832714a422496ddb894b08a
/usr/lib/systemd/system/auditd.service
/usr/libexec/audit-functions
/usr/libexec/initscripts/legacy-actions/auditd
/usr/libexec/initscripts/legacy-actions/auditd/condrestart
/usr/libexec/initscripts/legacy-actions/auditd/reload
/usr/libexec/initscripts/legacy-actions/auditd/restart
/usr/libexec/initscripts/legacy-actions/auditd/resume
/usr/libexec/initscripts/legacy-actions/auditd/rotate
/usr/libexec/initscripts/legacy-actions/auditd/state
/usr/libexec/initscripts/legacy-actions/auditd/stop
/usr/sbin/auditctl
/usr/sbin/auditd
/usr/sbin/augenrules
/usr/sbin/aureport
/usr/sbin/ausearch
/usr/sbin/autrace
/usr/share/audit
/usr/share/audit/sample-rules
/usr/share/audit/sample-rules/10-base-config.rules
/usr/share/audit/sample-rules/10-no-audit.rules
/usr/share/audit/sample-rules/11-loginuid.rules
/usr/share/audit/sample-rules/12-cont-fail.rules
/usr/share/audit/sample-rules/12-ignore-error.rules
/usr/share/audit/sample-rules/20-dont-audit.rules
/usr/share/audit/sample-rules/21-no32bit.rules
/usr/share/audit/sample-rules/22-ignore-chrony.rules
/usr/share/audit/sample-rules/23-ignore-filesystems.rules
/usr/share/audit/sample-rules/30-nispom.rules
/usr/share/audit/sample-rules/30-ospp-v42-1-create-failed.rules
/usr/share/audit/sample-rules/30-ospp-v42-1-create-success.rules
/usr/share/audit/sample-rules/30-ospp-v42-2-modify-failed.rules
/usr/share/audit/sample-rules/30-ospp-v42-2-modify-success.rules
/usr/share/audit/sample-rules/30-ospp-v42-3-access-failed.rules
/usr/share/audit/sample-rules/30-ospp-v42-3-access-success.rules
/usr/share/audit/sample-rules/30-ospp-v42-4-delete-failed.rules
/usr/share/audit/sample-rules/30-ospp-v42-4-delete-success.rules
/usr/share/audit/sample-rules/30-ospp-v42-5-perm-change-failed.rules
/usr/share/audit/sample-rules/30-ospp-v42-5-perm-change-success.rules
/usr/share/audit/sample-rules/30-ospp-v42-6-owner-change-failed.rules
/usr/share/audit/sample-rules/30-ospp-v42-6-owner-change-success.rules
/usr/share/audit/sample-rules/30-ospp-v42.rules
/usr/share/audit/sample-rules/30-pci-dss-v31.rules
/usr/share/audit/sample-rules/30-stig.rules
/usr/share/audit/sample-rules/31-privileged.rules
/usr/share/audit/sample-rules/32-power-abuse.rules
/usr/share/audit/sample-rules/40-local.rules
/usr/share/audit/sample-rules/41-containers.rules
/usr/share/audit/sample-rules/42-injection.rules
/usr/share/audit/sample-rules/43-module-load.rules
/usr/share/audit/sample-rules/44-installers.rules
/usr/share/audit/sample-rules/70-einval.rules
/usr/share/audit/sample-rules/71-networking.rules
/usr/share/audit/sample-rules/99-finalize.rules
/usr/share/audit/sample-rules/README-rules
/usr/share/doc/audit
/usr/share/doc/audit/ChangeLog
/usr/share/doc/audit/README
/usr/share/doc/audit/auditd.cron
/usr/share/licenses/audit
/usr/share/licenses/audit/COPYING
/usr/share/man/man5/auditd-plugins.5.gz
/usr/share/man/man5/auditd.conf.5.gz
/usr/share/man/man5/ausearch-expression.5.gz
/usr/share/man/man7/audit.rules.7.gz
/usr/share/man/man8/auditctl.8.gz
/usr/share/man/man8/auditd.8.gz
/usr/share/man/man8/augenrules.8.gz
/usr/share/man/man8/aulast.8.gz
/usr/share/man/man8/aulastlog.8.gz
/usr/share/man/man8/aureport.8.gz
/usr/share/man/man8/ausearch.8.gz
/usr/share/man/man8/ausyscall.8.gz
/usr/share/man/man8/autrace.8.gz
/usr/share/man/man8/auvirt.8.gz
/var/log/audit
/var/run/auditd.state
```

---

### misc(audit package)

```
# dnf search audit
마지막 메타자료 만료확인 0:04:14 이전인: 2022년 09월 28일 (수) 오전 03시 03분 55초.
=========================== 이름 & 요약과 일치하는 항목: audit ============================
audit.x86_64 : User space tools for kernel auditing
audit.src : User space tools for kernel auditing
audit-debuginfo.i686 : Debug information for package audit
audit-debuginfo.x86_64 : Debug information for package audit
audit-debugsource.i686 : Debug sources for package audit
audit-debugsource.x86_64 : Debug sources for package audit
audit-libs.x86_64 : Dynamic library for libaudit
audit-libs.i686 : Dynamic library for libaudit
audit-libs-debuginfo.i686 : Debug information for package audit-libs
audit-libs-debuginfo.x86_64 : Debug information for package audit-libs
audit-libs-devel.i686 : Header files for libaudit
audit-libs-devel.x86_64 : Header files for libaudit
pgaudit-debuginfo.x86_64 : Debug information for package pgaudit
pgaudit-debugsource.x86_64 : Debug sources for package pgaudit
python3-audit.x86_64 : Python3 bindings for libaudit
python3-audit-debuginfo.i686 : Debug information for package python3-audit
python3-audit-debuginfo.x86_64 : Debug information for package python3-audit
rsyslog-mmaudit.x86_64 : Message modification module supporting Linux audit format
rsyslog-mmaudit-debuginfo.x86_64 : Debug information for package rsyslog-mmaudit
sos-audit.noarch : Audit use of some commands for support purposes
=============================== 요약과 일치하는 항목: audit ===============================
```
