import IOCResponderLite.interfaces.cli.functions as Functions

import colorama

def StdOutput(checked_ioc):
    if checked_ioc.value:
        print(f'\n{colorama.Fore.MAGENTA}# RESULT for `{checked_ioc.value}{colorama.Fore.RESET}`')
    if checked_ioc.description:
        print(f'{colorama.Fore.CYAN}## DESCRIPTION:{colorama.Fore.RESET}')
        for description_item in checked_ioc.description:
            Functions.ColourOutput(f'- {description_item}')
    if checked_ioc.type == 'file':
        if checked_ioc.md5 or checked_ioc.sha256 or checked_ioc.sha1 or checked_ioc.ssdeep:
            print (f'{colorama.Fore.CYAN}## HASHES:{colorama.Fore.RESET}')
            if checked_ioc.md5:
                print(f'MD5: `{checked_ioc.md5}`')
            if checked_ioc.sha256:
                print(f'SHA256: `{checked_ioc.sha256}`')
            if checked_ioc.sha1:
                print(f'SHA1: `{checked_ioc.sha1}`')
            if checked_ioc.ssdeep:
                print(f'SSDEEP: `{checked_ioc.ssdeep}`')
        if checked_ioc.filenames:
            print(f'{colorama.Fore.CYAN}## FILENAMES:{colorama.Fore.RESET}')
            for file_item in checked_ioc.filenames:
                print(f'- {file_item}')
        if checked_ioc.family:
            print(f'{colorama.Fore.CYAN}## FAMILY:{colorama.Fore.RESET}')
            for family_item in checked_ioc.family:
                family_item_in_one_str = ' - '.join(str(value) for value in family_item.values())
                Functions.ColourOutput(family_item_in_one_str)
    if checked_ioc.type == 'ip':
        print (f'{colorama.Fore.CYAN}## IPINFO:{colorama.Fore.RESET}')
        if checked_ioc.hostname:
            print(f'HOSTNAME: `{checked_ioc.hostname}`')
        if checked_ioc.network:
            print(f'NETWORK: `{checked_ioc.network}`')
        if checked_ioc.asn:
            print(f'ASN: {checked_ioc.asn}')
        if checked_ioc.city:
            print(f'CITY: {checked_ioc.city}')
        if checked_ioc.region:
            print(f'REGION: {checked_ioc.region}')
        if checked_ioc.location:
            print(f'LOCATION: {checked_ioc.location}')
        if checked_ioc.org:
            print(f'ORG: {checked_ioc.org}')
        if checked_ioc.postal:
            print(f'POSTAL: {checked_ioc.postal}')
        if checked_ioc.whois:
            print(f'{colorama.Fore.CYAN}WHOIS: {colorama.Fore.RESET}')
            print(f'{checked_ioc.whois}')
    if checked_ioc.detect_vt:
        has_result = any(details.get('result') not in [None, 'clean', 'unrated'] for details in checked_ioc.detect_vt.values())
        if has_result:
            widths = {
                'AV': 25,
                'Result': 50
            }
            print(f'{colorama.Fore.CYAN}## VIRUSTOTAL:{colorama.Fore.RESET}\n|{'-'*80}|\n|{' AV':<27}|{' Result':<52}|\n|{'-'*27}|{'-'*52}|')
            for av, details in checked_ioc.detect_vt.items():
                av_result = {
                    'AV': av,
                    'Result': details.get('result')
                }
                if details.get('result') not in [None,'clean','unrated']:
                    Functions.PrintTable(av_result,widths)
            print(f'|{'-'*80}|')
    if checked_ioc.detect_other:
        if 'opentip' in checked_ioc.detect_other and checked_ioc.detect_other['opentip'] != None:
            widths = {
                    'Last detect': 25,
                    'Zone': 8,
                    'Detect': 40
            }
            detect_opentip = checked_ioc.detect_other.get('opentip', {})
            print(f'{colorama.Fore.CYAN}## OPENTIP:{colorama.Fore.RESET}')
            if detect_opentip.get('FileGeneralInfo', {}).get('Status'): Functions.ColourOutput(f'Status: {detect_opentip.get('FileGeneralInfo', {}).get('Status')}')
            if detect_opentip.get('FileGeneralInfo', {}).get('FileStatus'): Functions.ColourOutput(f'Status: {detect_opentip.get('FileGeneralInfo', {}).get('FileStatus')}')
            if detect_opentip.get('Zone'): Functions.ColourOutput(f'Zone: {detect_opentip.get('Zone')}')
            if detect_opentip.get('FileGeneralInfo', {}).get('HitsCount'): Functions.ColourOutput(f'Hits count: {detect_opentip.get('FileGeneralInfo', {}).get('HitsCount')}')
            if detect_opentip.get('FileGeneralInfo', {}).get('FirstSeen'): Functions.ColourOutput(f'First seen: {detect_opentip.get('FileGeneralInfo', {}).get('FirstSeen')}')
            if detect_opentip.get('FileGeneralInfo', {}).get('LastSeen'): Functions.ColourOutput(f'Last seen: {detect_opentip.get('FileGeneralInfo', {}).get('LastSeen')}')
            if detect_opentip.get('FileGeneralInfo', {}).get('Categories'): Functions.ColourOutput(f'Categories: {", ".join(detect_opentip.get('FileGeneralInfo', {}).get('Categories'))}')
            if detect_opentip.get('DetectionsInfo'):
                print(f'|{'-'*81}|\n| Last detect {' '*14}| Zone {' '*4}| Detect {' '*34}|\n|{'-'*27}|{'-'*10}|{'-'*42}|')
                for opentip_item_in_detects in detect_opentip.get('DetectionsInfo', {}):
                    opentip_results = {
                        'Last detect': opentip_item_in_detects['LastDetectDate'],
                        'Zone': opentip_item_in_detects['Zone'],
                        'Detect': opentip_item_in_detects['DetectionName']
                        }
                    Functions.PrintTable(opentip_results,widths)
                print(f'|{'-'*81}|')
        if 'avotx' in checked_ioc.detect_other and checked_ioc.detect_other['avotx'] != None:
            detect_alienvaultotx = checked_ioc.detect_other.get('avotx', {})
            print(f'{colorama.Fore.CYAN}## AlienVault OTX:{colorama.Fore.RESET}')
            print(f'Count: {detect_alienvaultotx.get('pulse_info',{}).get('count')}')
            if detect_alienvaultotx.get('pulse_info',{}).get('count') != 0:
                print(f'|{'-'*157}|\n| ID {' '*22}| Created {' '*19}| Modified {' '*18}| Name {' '*66}|\n|{'-'*26}|{'-'*28}|{'-'*28}|{'-'*72}|')
                widths = {
                    'id': 24,
                    'created': 26,
                    'modified': 26,
                    'name': 70
                }
                for pulse in detect_alienvaultotx.get('pulse_info',{}).get('pulses'):
                    Functions.PrintTable(pulse,widths)
                print(f'|{'-'*157}|')   
        if 'shodan' in checked_ioc.detect_other and checked_ioc.detect_other['shodan'] != None:
            detect_shodan = checked_ioc.detect_other.get('shodan', {})
            print(f'{colorama.Fore.CYAN}## SHODAN:{colorama.Fore.RESET}')
            for shodan_item in detect_shodan:
                if shodan_item:
                    if shodan_item.get('ip_str'): Functions.ColourOutput(f'### `{shodan_item['ip_str']}`:')
                    if shodan_item.get('hostnames'): Functions.ColourOutput(f'Hostnames: `{'`, `'.join(shodan_item['hostnames'])}`')
                    if shodan_item.get('domains'): Functions.ColourOutput(f'Domains: `{'`, `'.join(shodan_item['domains'])}`')
                    if shodan_item.get('country_name'): Functions.ColourOutput(f'Country: {shodan_item['country_name']}')
                    if shodan_item.get('region_code'): Functions.ColourOutput(f'Region: {shodan_item['region_code']}')
                    if shodan_item.get('city'): Functions.ColourOutput(f'City: {shodan_item['city']}')
                    if shodan_item.get('asn'): Functions.ColourOutput(f'ASN: {shodan_item['asn']}')
                    if shodan_item.get('isp'): Functions.ColourOutput(f'ISP: {shodan_item['isp']}')
                    if shodan_item.get('org'): Functions.ColourOutput(f'Organization: {shodan_item['org']}')
                    if shodan_item.get('os'): Functions.ColourOutput(f'OS: {shodan_item['os']}')
                    if shodan_item.get('tags'): Functions.ColourOutput(f'Tags: {', '.join(shodan_item['tags'])}')
                    if shodan_item.get('ports'): Functions.ColourOutput(f'Ports: {', '.join(map(str, shodan_item['ports']))}')
                    if shodan_item.get('vulns'): Functions.ColourOutput(f'Vulnerabilities: {', '.join(shodan_item['vulns'])}')                  
        if 'opencti' in checked_ioc.detect_other and checked_ioc.detect_other['opencti'] != None:
            detect_opencti = checked_ioc.detect_other.get('opencti', {})
            print(f'{colorama.Fore.CYAN}## OpenCTI:{colorama.Fore.RESET}')
            if detect_opencti.get('observable_data', {}).get('id'): Functions.ColourOutput(f'ID: {detect_opencti.get('observable_data', {}).get('id')}')
            if detect_opencti.get('observable_data', {}).get('entity_type'): Functions.ColourOutput(f'Type: {detect_opencti.get('observable_data', {}).get('entity_type')}')
            if detect_opencti.get('observable_data', {}).get('name'): Functions.ColourOutput(f'Name: {detect_opencti.get('observable_data', {}).get('name')}')
            if detect_opencti.get('observable_data', {}).get('value'): Functions.ColourOutput(f'Value: {detect_opencti.get('observable_data', {}).get('value')}')
            if detect_opencti.get('relations'):
                for rel in detect_opencti.get('relations', {}):
                    rel_type = rel['relationship_type']
                    other_party = rel['to'] if rel['from']['id'] == detect_opencti.get('observable_data', {}).get('id') else rel['from']
                    name = other_party.get('name') or other_party.get('value') or other_party['observable_value'] or 'Unknown' 
                    Functions.ColourOutput(f'  [{rel_type}] -> {name} ({other_party['entity_type']})')
        if 'ha' in checked_ioc.detect_other and checked_ioc.detect_other['ha'] != None:
            detect_hybridanalysis = checked_ioc.detect_other.get('ha', {})
            print(f'{colorama.Fore.CYAN}## HYBRID ANALYSIS:{colorama.Fore.RESET}')
            if detect_hybridanalysis.get('verdict'): Functions.ColourOutput(f'Verdict: {detect_hybridanalysis['verdict']}')
            if detect_hybridanalysis.get('threat_score'): Functions.ColourOutput(f'Score: {detect_hybridanalysis['threat_score'].__str__()}')
            if detect_hybridanalysis.get('submitted_at'): Functions.ColourOutput(f'Submitted at: {detect_hybridanalysis['submitted_at']}')
            if detect_hybridanalysis.get('analysis_start_time'): Functions.ColourOutput(f'Start of analise: {detect_hybridanalysis['analysis_start_time']}')
            if detect_hybridanalysis.get('last_multi_scan'): Functions.ColourOutput(f'Last multiscan: {detect_hybridanalysis['last_multi_scan']}')
            if detect_hybridanalysis.get('multiscan_result'): Functions.ColourOutput(f'Multiscan result: {detect_hybridanalysis['multiscan_result']}')
        if 'censys' in checked_ioc.detect_other and checked_ioc.detect_other['censys'] != None:
            widths = {
                    'Port': 5,
                    'Protocol': 8,
                    'Transport protocol': 9,
                    'Software info': 38,
                    'Version': 24,
                    'Server type': 23,
                    'Scan time': 20
            }
            censys_service = []
            censys_service_software = checked_ioc.detect_other.get('censys', {}).get('services', {})
            for censys_ports in censys_service_software:
                software_info = ', '.join([f"{s.get('vendor', 'Unknown')}, {s.get('product', 'Unknown')}" for s in      censys_ports.get('software', [])])
                version = censys_ports.get('dns', {}).get('version', 'Unknown version')
                server_type = censys_ports.get('dns', {}).get('server_type', 'Unknown server type')
                scan_time = censys_ports.get('scan_time', 'Unknown scan time')
                protocol = censys_ports.get('protocol', 'Unknown protocol')
                port = censys_ports.get('port', 'Unknown port')
                transport_protocol = censys_ports.get('transport_protocol', 'Unknown transport protocol').upper()
                result_dict = {
                    'Port': port,
                    'Protocol': protocol,
                    'Transport protocol': transport_protocol,
                    'Software info': software_info,
                    'Version': version,
                    'Server type': server_type,
                    'Scan time': scan_time
                }
                censys_service.append(result_dict)
            if censys_service:
                print(f'{colorama.Fore.CYAN}## SERVICES (from Censys):{colorama.Fore.RESET}')
                print(f'|{'-'*147}|\n| Port  | Protocol | Transport | Software {' '*30}| Version {' '*17}| Type {' '*19}| Scan time {' '*11}|\n|{'-'*7}|{'-'*10}|{'-'*11}|{'-'*40}|{'-'*26}|{'-'*25}|{'-'*22}|')
                for censys_services_item in censys_service:
                    Functions.PrintTable(censys_services_item,widths)
                print(f'|{'-'*147}|')
        if 'greynoise' in checked_ioc.detect_other and checked_ioc.detect_other['greynoise'] != None:
            greynoise = checked_ioc.detect_other.get('greynoise', {})
            keys = ['ip','noise','riot','classification','name','last_seen']
            if greynoise:
                print(f'{colorama.Fore.CYAN}## GREYNOISE:{colorama.Fore.RESET}')
                for greynoise_item in greynoise:
                    greynoise_item_in_one_str = '\n'.join(f'{key}: {value}' for key, value in zip(keys,greynoise_item))
                    Functions.ColourOutput(greynoise_item_in_one_str)
        if 'abuseipdb' in checked_ioc.detect_other and checked_ioc.detect_other['abuseipdb'] != None:
            abuseipdb = checked_ioc.detect_other.get('abuseipdb', {})
            print(f'{colorama.Fore.CYAN}## ABUSE IPDB:{colorama.Fore.RESET}')
            if abuseipdb.get('ipAddress'): Functions.ColourOutput(f'IP-Adress: `{abuseipdb.get('ipAddress')}`')
            if abuseipdb.get('isPublic'): Functions.ColourOutput(f'Public: {abuseipdb.get('isPublic')}')
            if abuseipdb.get('isWhitelisted'): Functions.ColourOutput(f'in Whitelist: {abuseipdb.get('isWhitelisted')}')
            if abuseipdb.get('usageType'): Functions.ColourOutput(f'Type: {abuseipdb.get('usageType')}')
            if abuseipdb.get('isp'): Functions.ColourOutput(f'ISP: {abuseipdb.get('isp')}')
            if abuseipdb.get('domain'): Functions.ColourOutput(f'Domain: `{abuseipdb.get('domain')}`')
            if abuseipdb.get('hostnames'): Functions.ColourOutput(f'Hostnames: `{"`, `".join(abuseipdb.get('hostnames', {}))}`')
            if abuseipdb.get('isTor'): Functions.ColourOutput(f'TOR: {abuseipdb.get('isTor')}')
            if abuseipdb.get('totalReports'): Functions.ColourOutput(f'Total reports: {abuseipdb.get('totalReports')}')
            if abuseipdb.get('lastReportedAt'): Functions.ColourOutput(f'Last reported: {abuseipdb.get('lastReportedAt')}') 
    if checked_ioc.type == 'domain' and checked_ioc.dns_records:
        print(f'{colorama.Fore.CYAN}## DNS Record: {colorama.Fore.RESET}')
        for dnsrecors_item in checked_ioc.dns_records:
            if dnsrecors_item:
                print(dnsrecors_item)
    return