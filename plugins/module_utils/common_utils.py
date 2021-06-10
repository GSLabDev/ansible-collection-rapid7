ANSIBLE_METADATA = {
    "metadata_version": "1.2",
    "status": ["preview"],
    "supported_by": "community",
}

from ansible.module_utils.basic import *
import json
import requests




def get_connection(client):
    try:
        hostname= client.params['hostname']
        username = client.params['username']
        password = client.params['password']
        return hostname,username,password
    except Exception as e:
        return ("Failed to get connection parameters for Rapid7 Instance",str(e))

def get_entity_id(url,module,payload=None,method=None):
        
        client = module
        hostname,username,password=get_connection(client)
        entity_id = None
        try:
            print("in get enrity id func")
            response = requests.get(url=url,auth=(username,password),json=payload,headers={'Content-Type':'application/json'},verify=False)
            parsed_response = json.loads(response.content)
            #print("resp2",parsed_response)
            for item in parsed_response['resources']:
                if item['name'] == payload:
                    entity_id = item['id']
                    print("id:",entity_id)
            if entity_id:
                return entity_id
            else:
                client.fail_json("Failed to get resource id for "+payload,changed=False)
        
        except Exception as e:
           return ("Failed to get id",str(e))

