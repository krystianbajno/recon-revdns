# How to use

Use rips to create list of IPs then feed it to the recon.
```bash
# Download rips release or compile from https://github.com/krystianbajno/rips
wget https://github.com/krystianbajno/rips/releases/download/release/rips-linux-x86 -O rips
wget https://github.com/krystianbajno/recon-revdns/releases/download/release/recon-revdns-linux-x86 -O recon-revdns
./rips 192.168.1.0/24 | ./recon-revdns -r <DNS SERVER IP>
```
