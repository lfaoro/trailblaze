# TrailBlaze - SSH Pentest & Audit

TrailBlaze is designed for security and devops teams to easily assess the most common vulnerability facing tech infrastructure in the wild (weak passwords & leaked keys).

## Features
- [x] SSH banner grabber
- [x] TCP scanner
- [ ] SSH version security audit
- [ ] SSH concurrent connector (execute remote commands)
- [ ] SSH password brute forcer
- [ ] SSH private key brute forcer

## Install
### Go
`$ go install github.com/lfaoro/trailblaze@latest`

### Release
https://github.com/lfaoro/trailblaze/releases

## Quick Start
```bash
$ trailblaze scan --lan --ports 80,22
INFO gathering local networks for localhost...
INFO randomizing hosts...
INFO starting scan using 1024 threads
OPEN[2] 192.168.0.1:80   1% [                    ]  [5s:4m23s]
$ tail scan.log

trailblaze banner -H scan.log
INFO loaded 202 hosts from scan.log file
INFO automatically set threads 10, use --threads to override.
SSH-2.0-dropbear found[22] 100% [====================]
$ tail banner.log
```

## Donations
If you're using this software in a for-profit company, please consider a donation.

Monero `8BcoUHbkB3RWmHFePv5Jmkfhfbx4CMAHvAZEMu7TsJGKMy6vfMWG12vKZh89TzwpvkgbJ5UJ7BZo3Nv1sHsLppXVCBgkYjC`

Bitcoin `bc1qmgxchawqzw2gpgswg3wn9ygae26thp3snwlyy6`

Paypal `https://paypal.me/lfaoro`

## Disclaimer
This software should be used for authorized penetration testing and/or educational purposes only.
Any misuse of this software will not be the responsibility of the author or of any other collaborator.
Use it on your own systems or obtain explicit permission from the systems owner.

Usage of this software for connecting to targets without prior mutual consent may be illegal in your jurisdiction.
It is your responsibility to obey all applicable local, state and federal laws.
We assume no liability and are not responsible for any misuse or damage caused.
