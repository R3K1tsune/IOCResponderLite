### IOC Responder Core
import time
import IOCResponderLite.core.requester as Request
import IOCResponderLite.core.modules as Modules
from IOCResponderLite.core.classes import *

def CheckIOC(value,type,service,args):
    match type:
        case 'file':
            checked_ioc = File()
            url = 'file_url'
        case 'ip':
            checked_ioc = IPAddress()
            url = 'ip_url'
        case 'domain':
            checked_ioc = Domain()
            url = 'domain_url'
    checked_ioc.value = value
    checked_ioc.type = type
    module_result = {}
    for service_name, service_config in service.items():
        if type == 'ip':
            if service_name == 'ipinfo' and ('ipinfo' in args.modules or 'all' in args.modules):
                result = Request.ApiRequest(service_name=service_name, service_config=service_config, endpoint=f'{checked_ioc.value}')
                if result.get('ip') != None:
                    checked_ioc.value = result.get('ip')
                    checked_ioc.hostname = result.get('hostname')
                    checked_ioc.city = result.get('city')
                    checked_ioc.region = result.get('region')
                    checked_ioc.location = result.get('loc')
                    checked_ioc.asn = result.get('org')
                    checked_ioc.postal = result.get('postal')
            elif service_name in Modules.modules_ip and (service_name in args.modules or 'all' in args.modules):
                function = Modules.modules_ip_function.get(service_name)
                if function: module_result[service_name] = function(service_config,url,checked_ioc)
        if service_name == 'vt' and ('vt' in args.modules or 'all' in args.modules):
            result = Request.ApiRequest(service_name=service_name, service_config=service_config, endpoint=f'{service_config.get(url)}{checked_ioc.value}')
            if result.get('data') != None:
                checked_ioc.md5 = result.get('data', {}).get('attributes', {}).get('md5')
                checked_ioc.sha256 = result.get('data', {}).get('attributes', {}).get('sha256')
                checked_ioc.sha1 = result.get('data', {}).get('attributes', {}).get('sha1')
                checked_ioc.ssdeep = result.get('data', {}).get('attributes', {}).get('ssdeep')
                checked_ioc.filename = result.get('data', {}).get('attributes', {}).get('names', {})
                checked_ioc.family = result.get('data', {}).get('attributes', {}).get('popular_threat_classification', {}).get('popular_threat_name', {})
                description_temp = []
                description_temp.append(result.get('data', {}).get('attributes',{}).get('magic'))
                signates_info = result.get('data', {}).get('attributes', {}).get('signature_info', {})
                for key, value in signates_info.items():
                    description_temp.append(f"{key.capitalize()}: {value}")
                known_distributors = result.get('data', {}).get('attributes', {}).get('known_distributors', {})
                for key, value in known_distributors.items():
                    description_temp.append(f"{key.capitalize()}: {value}")
                checked_ioc.description = description_temp
                checked_ioc.detect_vt = result.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
                time.sleep(int(service_config.get('sleep')))
        elif service_name in Modules.modules_universal and (service_name in args.modules or 'all' in args.modules):
            function = Modules.modules_universal_function.get(service_name)
            if function: 
                module_result[service_name] = function(service_config,url,checked_ioc)
    checked_ioc.detect_other = module_result
    if checked_ioc: return checked_ioc            
    else: return None
