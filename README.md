# Password Cracker SNMPv3

This project is a Python-based tool designed to crack passwords by computing HMAC-MD5 values. It attempts to find the correct password from a wordlist by comparing the computed HMAC-MD5 with a given target authentication parameter.

## Features

- Calculates HMAC-MD5 required for password verification.
- Uses a wordlist to attempt password cracking.
- Displays progress and estimated time using `tqdm`.
- Formats time in a human-readable format.
- Utilizes `colorama` for colored console output.

## Prerequisites

- Python 3.x
- `tqdm` library
- `colorama` library

You can install the required libraries using pip:

```sh
pip install tqdm colorama
```

### Usage
**1. Clone the repository:**

```sh
git clone https://github.com/youcefKNL/Password_Cracker_SNMPv3.git
cd Password_Cracker_SNMPv3
```
**2. Ensure you have a wordlist file (e.g., wordlist.txt).**

```sh
./snmp_md5_cracker.py
```

**3. Follow the prompts to enter:**

- msgAuthoritativeEngineID (SNMP Agent ID)
- msgAuthenticationParameters (Controls authenticity and message integrity)
- msgWhole (SNMPv3 whole message where msgAuthenticationParameters value is being replaced by 12 \x00 bytes)
- Path to the wordlist file

# Example
```sh
Enter 'msgAuthoritativeEngineID' (SNMP Agent ID): 80004fb805636c6f75644dab22cc
Enter 'msgAuthenticationParameters' (Controls authenticity and message integrity): e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4
Enter 'msgWhole' (SNMPv3 whole message where msgAuthenticationParameters value is being replaced by 12 \x00 bytes): 302e02010330110204111f3515020200c0040107020103042065cdefd5b1f8eb13e4e8db0e43d4b5e3
Enter the path to the wordlist file: wordlist.txt
Processing:  46%|█████████████████▌            | 50978/109871 [02:37<02:58, 329.77it/s]
Elapsed Time: 0 years 0 days 0 hours 2 minutes 37 seconds
Est. Total Time: 0 years 0 days 0 hours 5 minutes 35 seconds
```
