### IOCResponderLite CLI
import argparse, colorama
import IOCResponderLite.core.functions
import IOCResponderLite.interfaces.cli.functions
import IOCResponderLite.interfaces.cli.output as Output
import IOCResponderLite.core.main as Main
from IOCResponderLite.core.classes import *

def main():
    parser = argparse.ArgumentParser(description='IOC Responder Lite\n'
                                            'CLI-utility for checking IOC`s (MD5, SHA1, SHA256, IP addresses and domains on various platforms)\n'
                                            'Author: R3狐 (R3K)\nVersion: 1.0.2\n\n'
                                            'Support online platforms:\n'
                                            '|-------------------------------------------------------|\n'
                                            '| Key       | Description                               |\n'
                                            '|-----------|-------------------------------------------|\n'
                                            '| ipinfo    | IPInfo                                    |\n'
                                            '| vt        | VirusTotal                                |\n'
                                            '| opentip   | Kaspersky Open Threat Intelligence Portal |\n'
                                            '| ha        | Hybrid Analysis                           |\n'
                                            '| censys    | Censys                                    |\n'
                                            '| greynoise | GreyNoise                                 |\n'
                                            '| abuseip   | AbuseIP DB                                |\n'
                                            '| avotx     | AlienVault OTX                            |\n'
                                            '| shodan    | Shodan                                    |\n'
                                            '| opencti   | OpenCTI                                   |\n'
                                            '|-------------------------------------------------------|'
                                            , formatter_class=argparse.RawTextHelpFormatter)
    hashes, ips, domains = [], [], []
    modules = {'ipinfo','vt',
           'opentip', 'ha', 'censys', 'greynoise',
           'abuseip', 'avotx', 'shodan', 'opencti',
           'all'}
    def CreateList(value: str):
        items = [x.strip() for x in value.split(',')]
        invalid = set(items) - modules
        if invalid:
            raise argparse.ArgumentTypeError(f'Invalid module: {', '.join(invalid)}')
        return items
    parser.add_argument('-t', '--target', dest='ioc', help='Any IOC: Hash (MD5, SHA256, SHA1), IP-address (1.2.3.4, 1.2.3[.]4) or Domain Domain (example.com, example[.]net)', nargs='+', default='none', type=str)
    parser.add_argument('-m', '--modules', dest='modules', help='Use difinite modules, btw "ktip, vt". By default - all', default='all', type=CreateList)
    parser.add_argument('-f', '--file', dest='path_to_iocs_file', help='Path to file with IOC`s', default='none', type=str)
    parser.add_argument('-c', '--config', dest='path_to_config', help='Path to configuration file', default='none', type=str)
    parser.add_argument('-j', '--json', dest='path_to_json_output', help='path to folder for generate JSON-files', default='none', type=str)
    parser.add_argument('-s', '--silent', dest='silent', help='SILENT-mode: don`t show stdout', action='store_true')
    args = parser.parse_args()
    configuration = IOCResponderLite.interfaces.cli.functions.InitConfig(args.path_to_config)

    IOCResponderLite.interfaces.cli.functions.Banner()
    full_result = []
    if args.ioc != 'none':
        any_iocs = args.ioc
        for ioc in any_iocs:
            any_ioc_type = IOCResponderLite.core.functions.DetermineIocType(ioc)
            match any_ioc_type:
                case 'MD5' | 'SHA256' | 'SHA1':
                    hashes.append(ioc)
                case 'IPv4':
                    ips.append(ioc)
                case 'Domain':
                    domains.append(ioc)
                case _:
                    print(f'{colorama.Fore.RED}Unknown type of IOC `{ioc}`{colorama.Fore.RESET}')
    if args.path_to_iocs_file != 'none':    
        hashes = IOCResponderLite.interfaces.cli.functions.ReadIOCsFile(args.path_to_iocs_file,'Hashes')
        ips = IOCResponderLite.interfaces.cli.functions.ReadIOCsFile(args.path_to_iocs_file,'IPs')
        domains = IOCResponderLite.interfaces.cli.functions.ReadIOCsFile(args.path_to_iocs_file,'Domains')
    if hashes != []:
        for hash_item in hashes:
            if IOCResponderLite.core.functions.DetermineIocType(hash_item) in ('MD5','SHA256','SHA1'):
                full_result.append(Main.CheckIOC(hash_item,'file',configuration.get('services', {}),args))
    if ips != []:
        for ip_item in ips:
            if '[' in ip_item or ']' in ip_item:
                ip_item = IOCResponderLite.core.functions.ConvertString(ip_item)
            full_result.append(Main.CheckIOC(ip_item,'ip',configuration.get('services', {}),args))
    if domains != []:
        for domain_item in domains:
            if '[' in domain_item or ']' in domain_item:
                domain_item = IOCResponderLite.core.functions.ConvertString(str(domain_item))
            full_result.append(Main.CheckIOC(domain_item,'domain',configuration.get('services', {}),args))
    if full_result:
        for result in full_result: 
            if not args.silent:
                Output.StdOutput(result)
            if args.path_to_json_output != 'none':
                DataToJSON = result.JSONOutput()
                IOCResponderLite.interfaces.cli.functions.CreateFileOutput(DataToJSON,args.path_to_json_output,result.value) 

if __name__ == '__main__':
    main()                     