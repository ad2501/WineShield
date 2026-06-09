# ------------------------------------------------------------------
# Compatibility wrapper for the canonical WineShield Wine profile.
# ------------------------------------------------------------------

#include <tunables/global>

profile wine-profile /usr/bin/wine{64,}{,-preloader} flags=(attach_disconnected) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  owner @{HOME}/.wine/** rw,
  owner @{HOME}/.wineshield/** rw,
  owner @{HOME}/.cache/wine/** rw,

  /usr/bin/wine{64,} mr,
  /usr/bin/wine{64,}-preloader mr,
  /usr/bin/wineserver ix,

  /usr/lib/** rm,
  /usr/lib32/** rm,
  /usr/lib64/** rm,
  /lib/** rm,
  /lib32/** rm,
  /lib64/** rm,

  owner /tmp/** rw,
  owner /var/tmp/** rw,

  /dev/null rw,
  /dev/zero rw,
  /dev/urandom r,
  /dev/dri/** rw,
  /dev/snd/** rw,
  /dev/pts/** rw,

  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,
  network unix stream,
  network unix dgram,

  @{PROC}/@{pid}/** r,
  /sys/devices/** r,

  deny /etc/shadow r,
  deny owner @{HOME}/.ssh/** r,
  deny owner @{HOME}/.gnupg/** r,
}
