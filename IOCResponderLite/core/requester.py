import requests, logging
import urllib3 # if a self-signed certificate is used
from pycti import OpenCTIApiClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # if a self-signed certificate is used
logging.getLogger('pycti').disabled = True
logging.getLogger('api').disabled = True

def ApiRequest(service_name: str, 
                service_config: dict,               
                endpoint: str,
                method: str = 'GET',
                params: dict | None = None,
                data: dict | None = None,
                json_data: dict | None = None,
                timeout: int = 15) -> dict: 
    base_url = service_config.get('base_url')
    api_key = service_config.get('api_key')
    headers_cfg = service_config.get('headers', {})
    headers = {}
    for k, v in headers_cfg.items():
        headers[k] = v.format(api_key=api_key)
    url = f'{base_url}{endpoint}'
    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=data,
            json=json_data,
            timeout=timeout
        )
        response.raise_for_status()
        if response.content:
            return response.json()
        return {'status': 'ok', 'message': 'Empty response'}
    except requests.exceptions.HTTPError as error:
        return {
            'error': 'HTTPError',
            'service': service_name,
            'status_code': response.status_code,
            'response': response.text
        }
    except requests.exceptions.RequestException as error:
        return {
            'error': 'RequestException',
            'service': service_name,
            'message': str(error)
        }

def OpenCTIRequest(server,token,ioc,type):
    try:
        client = OpenCTIApiClient(server,token,ssl_verify=False) # if a self-signed certificate is used
    except:
        return
    if type == 'file':
        if len(ioc) == 32: key = 'hashes.MD5'
        elif len(ioc) == 40: key = 'hashes.SHA-1'
        elif len(ioc) == 64: key = 'hashes.SHA-256'
    elif type == 'ip' or type == 'domain': key = 'value'
    observable = client.stix_cyber_observable.read(
        filters={
            'mode': 'and',
            'filters': [{
                'key': key,
                'values': [ioc]}],
            'filterGroups': []
        }
    )
    if observable:
        result = []
        rels = client.stix_core_relationship.list(fromOrToId=observable['id'],)
        result = {
            'observable_data':observable,
            'relations':rels
        }
        return result 
    else:
        return None
    
if __name__ == '__main__':
    print('Please run main `.py` file')