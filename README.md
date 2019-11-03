## zonetransfer-dump
Dump DNS records from misconfigured DNS.

This script will automatically retrieve and dump all DNS records from misconfigured DNS into JSON formatted file. This script is using Python 3.

### Installation
- Clone this repository. (`git clone https://github.com/aqhmal/zonetransfer_dump.git`)
- Install from requirements.txt. (`pip3 install -r requirements.txt`).

### Usage
`python3 dumper.py <domain or URL>`

For example,

`python3 dumper.py testing.com`

Also can be used for multiple domains.

`python3 dumper.py testing.com test.com test.net https://www.test.com http://test123.com`