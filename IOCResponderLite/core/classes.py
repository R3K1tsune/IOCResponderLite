import json

class IOC:
    def __init__(self=None,
                 value=None,
                 type=None,
                 description=None,
                 detect_vt=None,
                 detect_other=None,
                ):
        self.value = value
        self.type = type
        self.description = description
        self.detect_vt = detect_vt
        self.detect_other = detect_other
    def __repr__(self):
        return f'IOC(value={self.value}, type={self.type}, description={self.description}, detect_vt={self.detect_vt}), detect_other={self.detect_other}'
    def IsDefault(self):
        return all(value is None for value in vars(self).values())
    def JSONOutput(self):
        return json.dumps(self.__dict__,indent=4, separators=(',', ': '), ensure_ascii=False)

class File(IOC):
    def __init__(self,
                 md5=None,
                 sha256=None,
                 sha1=None,
                 ssdeep=None,
                 filenames=None,
                 family=None
                ):
        super().__init__()
        self.md5 = md5
        self.sha256 = sha256
        self.sha1 = sha1
        self.ssdeep = ssdeep
        self.filenames = filenames
        self.family = family
    def __repr__(self):
        super().__repr__()
        return f'File(md5={self.md5}, sha256={self.sha256}, sha1={self.sha1}), ssdeep={self.ssdeep}, family={self.family}'
    def IsDefault(self):
        super().IsDefault()
        return all(value is None for value in vars(self).values())
    def JSONOutput(self):
        super().JSONOutput()
        return json.dumps(self.__dict__,indent=4, separators=(',', ': '), ensure_ascii=False)

class IPAddress(IOC):
    def __init__(self, 
                hostname=None,
                network=None,
                asn=None,
                city=None,
                region=None,
                location=None,
                org=None,
                postal=None,
                whois=None
                ):
        super().__init__()
        self.hostname = hostname
        self.network = network
        self.asn = asn
        self.city = city
        self.region = region
        self.location = location
        self.org = org
        self.postal = postal
        self.whois = whois
    def __repr__(self):
        super().__repr__()
        return f'IPAddress(hostname={self.hostname}, network={self.network}, org={self.org}, asn={self.asn}, city={self.city}, region={self.region}, location={self.location}, postal={self.postal}, whois={self.whois}'
    def IsDefault(self):
        super().IsDefault()
        return all(value is None for value in vars(self).values())
    def JSONOutput(self):
        super().JSONOutput()
        return json.dumps(self.__dict__,indent=4, separators=(',', ': '), ensure_ascii=False)

class Domain(IOC):
    def __init__(self, 
                dns_records=None
                ):
        super().__init__()
        self.dns_records = dns_records
    def __repr__(self):
        super().__repr__()
        return f'Domain(dns_records={self.dns_records}'
    def IsDefault(self):
        super().IsDefault()
        return all(value is None for value in vars(self).values())
    def JSONOutput(self):
        super().JSONOutput()
        return json.dumps(self.__dict__,indent=4, separators=(',', ': '), ensure_ascii=False)

if __name__ == '__main__':
    print('Please run main `.py` file')