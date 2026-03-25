import re, ipaddress

def DetermineIocType(value):
    if not isinstance(value, str):
        print(f'IOC {value} is not str()!!!')
        return None
    value = value.lower()
    value = ConvertString(value)
    hash_patterns = {
        'MD5': r'^[0-9a-f]{32}$',
        'SHA1': r'^[0-9a-f]{40}$',
        'SHA256': r'^[0-9a-f]{64}$'
    }
    domain_pattern = r'^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,}$'
    for hash_name, pattern in hash_patterns.items():
        if re.fullmatch(pattern, value):
            return hash_name
    try:
        ip = ipaddress.ip_address(value)
        if isinstance(ip, ipaddress.IPv4Address):
            return 'IPv4'
    except ValueError:
        pass  
    if re.fullmatch(domain_pattern, value):
        return 'Domain'
    return None

def ConvertString(string):
    string = string.replace('[','').replace(']','')
    return string

if __name__ == '__main__':
    print('Please run main `.py` file')