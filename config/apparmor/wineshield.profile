# ------------------------------------------------------------------
# WineShield launcher umbrella profile.
# ------------------------------------------------------------------

#include <tunables/global>

profile wineshield /usr/bin/wineshield flags=(attach_disconnected) {
  #include <abstractions/base>
  #include <abstractions/python>

  /usr/bin/python3* ix,
  /usr/bin/wine{64,}{,-preloader} ix,
  /usr/bin/wineserver ix,
  /usr/bin/Xephyr ix,

  owner @{HOME}/.wineshield/** rw,
  /etc/wineshield/** r,
  /var/log/wineshield/** rw,
  @{PROC}/@{pid}/** r,
  /sys/fs/cgroup/** r,

  network inet stream,
  network unix stream,

  capability sys_admin,
  capability sys_ptrace,
  capability net_admin,
}
