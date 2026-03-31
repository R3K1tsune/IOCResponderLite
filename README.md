# IOC Responder
```bash
 _____ _____ _____    _____                       _ 
|     |     |     |  | __  |___ ___ ___ ___ ___ _| |___ ___ 
||   || ||| |   |||  |    -| -_|_ -| . | . |   | . | -_|  _|
|_____|_____|_____|  |__|__|___|___|  _|___|_|_|___|___|_|
                                   |_|LITE
```
Version: `1.0.2`
CLI-utility for checking IOC's on various online platforms with use API
## Support types of IOC's:
- Hashes (**md5**, **sha256**, **sha1**)
- IP-address (`1.2.3.4` or `1.2.3[.]4`)
- Domains (`example.com`, `example[.]net`)
## Support online platforms:
- [IPInfo](https://ipinfo.io/)
- [VirusTotal](https://www.virustotal.com/)
- [Kaspersky Open Threat Intelligence Portal](https://opentip.kaspersky.com/)
- [Hybrid Analysis](https://hybrid-analysis.com/)
- [Censys](https://search.censys.io/)
- [GreyNoise](https://viz.greynoise.io/)
- [AbuseIP DB](https://www.abuseipdb.com/)
- [AlienVault OTX](https://otx.alienvault.com)
- [Shodan](https://www.shodan.io/)
- [OpenCTI](https://github.com/opencti-platform/opencti)

> [!NOTE]
> U must have API-keys for use this tool

# Install
1. Download `.whl` or `.tar.gz` from **Releases**
2. Install **venv**:
```bash
python3 -m venv venv
```
3. Install package:
```bash
./venv/bin/pip install iocresponderlite-1.0.2-py3-none-any.whl
```
or
```bash
./venv/bin/pip install iocresponderlite-1.0.2.tar.gz
```

> [!NOTE]
> If you need OpenCTI, you need install `pycti` package version for your OpenCTI instance, or change requirement in `pyproject.toml` and build from sources

4. Download `settings.yml`, uncomment needed services and add your API keys:
5. Check installation:
```bash
./venv/bin/IOCResponderLite -h
```
6. Enjoy:
```bash
./venv/bin/IOCResponderLite -c settings.yml -t "8.8.8[.]8"
```
# Usage
```bash
usage: IOCResponderLite [-h] [-t IOC [IOC ...]] [-m MODULES] [-f PATH_TO_IOCS_FILE] 
                        [-c PATH_TO_CONFIG] [-j PATH_TO_JSON_OUTPUT] [-s]
```
> [!NOTE]
> If you use the utility on macOS, you must pass IP-addresses to the arguments as follows
> ```bash
> python3 -m IOCResponderLite -t "1.1.1.1" "8.8.8[.]8"
> ```

## Arguments
|Key|Description|
|-|-|
|`-t, --target`|Check IOC: Hash (MD5, SHA256, SHA1), IP-address (1.2.3.4, 1.2.3[.]4) or Domain (btw example.com, example[.]net). Use ` `(space) as delimetr|
|`-m, --modules`|Use difinite modules, btw `opentip, vt`. Use `,` as delimetr. By default - `all`|
|`-f, --file <PATH TO IOCS FILE>`|Path to file with IOCs|
|`-c, --config <PATH TO CONFIG>`|Path to configuration file|
|`-j, --json <PATH TO JSON DUMPS>`|The path to the folder for creating JSON files|
|`-s, --silent`|**SILENT**-mode: not show stdout|
|`-h, --help`|Show help|
## Modules
|Module|Description|
|-|-|
|`ipinfo`|IPInfo|
|`vt`|VirusTotal|
|`opentip`|Kaspersky Open Threat Intelligence Portal|
|`ha`|Hybrid Analysis|
|`censys`|Censys|
|`greynoise`|GreyNoise|
|`abuseip`|AbuseIP DB|
|`avotx`|AlienVault OTX|
|`shodan`|Shodan|
|`opencti`|OpenCTI|
## Configuration file
To use the utility, you must have API keys to the specified platforms. The configuration file format is shown below:
```json
### Configuration
services:
  ipinfo:
    api_key: ""
    base_url: "https://ipinfo.io/"
    headers:
      Authorization: "Bearer"
      Content-Type: "application/json"
  vt:
    api_key: ""
    base_url: "https://www.virustotal.com/api/v3"
    file_url: "/files/"
    domain_url: "/domains/"
    ip_url: "/ip_addresses/"
    headers:
      x-apikey: "{api_key}"
    sleep: "12"
  opentip:
    api_key: ""
    base_url: "https://opentip.kaspersky.com/api/v1"
    file_url: "/search/hash?request="
    domain_url: "/search/domain?request="
    ip_url: "/search/ip?request=" 
    headers:
      x-api-key: "{api_key}"
      Content-Type: "application/json"
  ha:
    api_key: ""
    base_url: "https://hybrid-analysis.com/api/v2"
    file_url: "/overview/"
    headers:
      api-key: "{api_key}"
      accept: "application/json"
  censys:
    api_key: ""
    base_url: "https://api.platform.censys.io/v3"
    ip_url: "/global/asset/host/"
    headers:
      Authorization: "Bearer {api_key}"
      Accept: "application/vnd.censys.api.v3.host.v1+json"
  greynoise:
    api_key: ""
    base_url: "https://api.greynoise.io/v3/community/"
    headers:
      key: "{api_key}"
  abuseipdb:
    api_key: ""
    base_url: "https://api.abuseipdb.com/api/v2"
    ip_url: "/check"
    days: "30"
    headers:
      Key: "{api_key}"
      Accept: "application/json"
  avotx:
    api_key: ""
    base_url: "https://otx.alienvault.com/api/v1/indicators"
    ip_url: "/IPv4/"
    file_url: "/file/"
    domain_url: "/domain/"
    headers:
      Key: "{api_key}"
      Accept: "application/json"
  shodan:
    api_key: ""
    base_url: "https://api.shodan.io/shodan/host"
    ip_url: "/"
    domain_url: "/search"
  opencti:
    api_key: ""
    base_url: "https://<your_domain>/graphql"
```
A template for the specified configuration (`settings.yml`) is provided along with the utility.
## Template of IOC's-file
Below is an example of a file with indicators (`iocs.txt`).
Indicators of various types are added from a new line to the corresponding section:
```ini
### Hashes
7765206c6f76652064666972203c3320
3d3d20676f6f64206c75636b212c2020676f6f642068756e74696e6721203d3d
### IPs
1.1.1.1
8.8.8[.]8
### Domains
yahoo.net
google[.]com
```
# Examples
1. Check files by **md5** and **sha1** hash:
```bash
python3 -m IOCResponderLite -t a9e390237a96e0c6655b1a06f8d72c6f 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```
2. Check ip's `1.1.1.1` and `8.8.8.8`:
```bash
python3 -m IOCResponderLite -t 1.1.1.1 8.8.8[.]8
```
3. Check domains google.com and yahoo.net:
```bash
python3 -m IOCResponderLite -t yahoo.net google[.]com
```
4. Check IP, Domains and Hashes:
```bash
python3 -m IOCResponderLite -t 8.8.8[.]8 a9e390237a96e0c6655b1a06f8d72c6f google[.]com
```
5. Check IP, Hashes only on IPInfo.io and VirusTotal 
```bash
python3 -m IOCResponderLite -m ipinfo,vt -t 8.8.8.8 a9e390237a96e0c6655b1a06f8d72c6f
```
6. Use external configuration file:
```bash
python3 -m IOCResponderLite -t google[.]com -c D:\external_settings.yaml
```
7. Check IOC's from file `D:\examples\iocs.txt`:
```bash
python3 -m IOCResponderLite -f iocs.txt
```
8. Check IOC's form file `D:\examples\iocs.txt` and save result in JSON-files:
```bash
python3 -m IOCResponderLite -f iocs.txt -j D:\Results\JSON
```
9. Check IOC's form file `D:\examples\iocs.txt` and save result in JSON-files with **silent** mode:
```bash
python3 -m IOCResponderLite -f iocs.txt -j D:\Results\JSON -s
```