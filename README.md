# EmailRecon-Jay

A comprehensive email reconnaissance tool created by Jay Mali that performs DNS lookups, WHOIS queries, reputation checks, and generates Google search dorks for OSINT investigations.

## Features

- 📧 Email format validation using regex
- 🔍 DNS MX record lookup using dnspython
- 🌐 WHOIS domain information lookup
- ⚡ Email reputation check via emailrep.io API
- 🔎 Google dorks generation for OSINT
- 📊 Clean terminal output with [+]/[-] formatting
- ⚠️ Comprehensive error handling

## Installation

### Windows
1. Clone the repository:
```bash
git clone https://github.com/masterjay2911/EmailRecon-Jay.git
cd EmailRecon-Jay
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

### Linux/Ubuntu
1. Clone the repository:
```bash
git clone https://github.com/masterhexo/EmailRecon-Jay.git
cd EmailRecon-Jay
```

2. Install Python3 and pip if not already installed:
```bash
sudo apt update
sudo apt install python3 python3-pip
```

3. Install the required dependencies:
```bash
pip3 install -r requirements.txt
```
or
```bash
python3 -m pip install -r requirements.txt
```

If you get a permission error, you can use:
```bash
sudo pip3 install -r requirements.txt
```

## Usage

Basic usage:
```bash
python emailrecon_jay.py <email@domain.com>
```

Alternative usage with -e flag:
```bash
python emailrecon_jay.py -e <email@domain.com>
```

## Features in Detail

1. **DNS MX Record Lookup**
   - Retrieves mail server information
   - Shows priority levels
   - Displays full server hostnames

2. **WHOIS Information**
   - Domain registration details
   - Creation and expiration dates
   - Registrar information
   - Name servers

3. **Email Reputation Check**
   - Uses emailrep.io API
   - Shows reputation score
   - Identifies suspicious patterns
   - Lists associated tags

4. **Google Dorks Generation**
   - General email presence
   - Pastebin appearances
   - Social media profiles
   - Document searches
   - Data breach mentions

## Example Output

```
╔══════════════════════════════════════════════════════════════╗
║                        EmailRecon-Jay                        ║
║                  Email Reconnaissance Tool                   ║
║                         Version 1.0                         ║
║                      Created by Jay                         ║
╚══════════════════════════════════════════════════════════════╝

[+] Starting reconnaissance for: example@domain.com
[+] Extracted domain: domain.com

[+] DNS MX Record Lookup for domain.com
==================================================
[+] Found MX records...

[Additional output sections...]
```

## Notes

- The emailrep.io API has rate limiting on the free tier
- Tool is for educational and legitimate security research purposes only
- Always ensure proper authorization before investigating email addresses

## Requirements

- Python 3.x
- dnspython
- python-whois
- requests

## Creator

Created by Jay Mali

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and legitimate security research purposes only. Users must ensure they have proper authorization before investigating any email addresses. The creator is not responsible for any misuse of this tool.
