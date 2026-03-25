import IOCResponderLite.core.requester as Request

def censys(module_config,url,checked_ioc):
    censys_result = []
    result = Request.ApiRequest(service_name='censys', service_config=module_config, endpoint=f'{module_config.get(url)}{checked_ioc.value}')
    if result.get('result'): 
        censys_result = result.get('result',{}).get('resource',{})
        return censys_result
def greynoise(module_config,url,checked_ioc):
    greynoise_result = []
    result = Request.ApiRequest(service_name='greynoise', service_config=module_config, endpoint=f'{module_config.get(url)}{checked_ioc.value}')
    if result.get('ip'): 
        greynoise_result = result
        return greynoise_result
def abuseipdb(module_config,url,checked_ioc):
    abuseipdb_result = []
    abuseipdb_params = {
                    'ipAddress': checked_ioc.value,
                    'maxAgeInDays': module_config['days'],
                    'verbose': 'verbose'
    }
    result = Request.ApiRequest(service_name='abuseipdb', service_config=module_config, endpoint=f'{module_config.get(url)}', params=abuseipdb_params)
    if result.get('data'): 
        abuseipdb_result = result.get('data')
        return abuseipdb_result
def opentip(module_config,url,checked_ioc):
    opentip_result = []
    result = Request.ApiRequest('opentip', service_config=module_config, endpoint=f'{module_config.get(url)}{checked_ioc.value}', timeout=60)
    if result.get('Zone'): 
        opentip_result = result
        return opentip_result
def shodan(module_config,url,checked_ioc):
    shodan_description = []
    if url == 'ip_url':
        result = Request.ApiRequest(service_name='shodan', service_config=module_config, endpoint=f'{module_config.get(url)}{checked_ioc.value}?key={module_config.get('api_key')}', timeout=60)
        if result.get('error'): 
            return 
        shodan_description.append(result)
    elif url == 'domain_url':
        result = Request.ApiRequest(service_name='shodan', service_config=module_config, endpoint=f'{module_config.get(url)}?key={module_config.get('api_key')}&query=hostname:{checked_ioc.value}', timeout=60)
        if result.get('error'): 
            return  
        for item in result.get('matches', {}):
            shodan_description.append(item)
    if shodan_description: return shodan_description
def avotx(module_config,url,checked_ioc):
    otx_result = []
    result = Request.ApiRequest(service_name='avotx', service_config=module_config, endpoint=f'{module_config.get(url)}{checked_ioc.value}/general', timeout=120)
    if result.get('pulse_info'): 
        otx_result = result
        return otx_result
def ha(module_config,url,checked_ioc):
    if checked_ioc.type == 'file':     
        hybridanalysis_result = []
        result = Request.ApiRequest(service_name='ha', service_config=module_config, endpoint=f'{module_config.get(url)}{checked_ioc.sha256}/summary')
        if result.get('sha256'): 
            hybridanalysis_result = result
            return hybridanalysis_result
def opencti(module_config,url,checked_ioc):
    opencti_result = []
    result = Request.OpenCTIRequest(module_config.get('base_url'),module_config.get('api_key'),checked_ioc.value)
    if result: 
        opencti_result = result
        return opencti_result

modules_universal = [
    'opentip',
    'shodan',
    'avotx',
    'ha',
    'opencti']
modules_ip = [
    'censys',
    'greynoise',
    'abuseipdb']
modules_universal_function = {
    'opentip':opentip,
    'shodan':shodan,
    'avotx':avotx,
    'ha':ha,
    'opencti':opencti
}
modules_ip_function = {
    'censys':censys,
    'greynoise':greynoise,
    'abuseipdb':abuseipdb
}