# ------------------------------------------------------------------
# Compatibility wrapper for the canonical WineShield wineserver profile.
# ------------------------------------------------------------------

#include <tunables/global>

profile wineserver-profile /usr/bin/wineserver flags=(attach_disconnected) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  owner @{HOME}/.wine/** rw,
  owner @{HOME}/.wineshield/** rw,
  owner @{HOME}/.cache/wine/** rw,

  /usr/bin/wineserver mr,
  /usr/lib/** rm,
  /usr/lib32/** rm,
  /usr/lib64/** rm,
  /lib/** rm,
  /lib32/** rm,
  /lib64/** rm,

  owner /tmp/** rw,
  owner /var/tmp/** rw,

  network unix stream,
  network unix dgram,
  network inet stream,
  network inet6 stream,

  @{PROC}/@{pid}/** r,
}
