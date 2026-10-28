# kxprovd serial device and systemd `DeviceAllow`

Production unit [`kxprovd.service`](kxprovd.service) uses `DevicePolicy=closed` with an explicit
allow list. Sim transport does not open the serial device; serial transport requires read/write
access to the path in daemon config (`serial_device`, default `/dev/kxpbx`).

If your PBX device node is not `/dev/kxpbx`, add a drop-in:

```ini
# /etc/systemd/system/kxprovd.service.d/serial-device.conf
[Service]
DeviceAllow=
DeviceAllow=char-rtc r
DeviceAllow=char-random r
DeviceAllow=char-urandom r
DeviceAllow=/dev/null rw
DeviceAllow=/dev/your-pbx-device rw
```

Then `systemctl daemon-reload` and restart `kxprovd`.
