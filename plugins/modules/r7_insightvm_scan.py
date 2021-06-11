
#!/usr/bin/python

ANSIBLE_METADATA = {
    "metadata_version": "1.2",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r'''
---
module: r7_insightvm_scan

short_description: Module to create a scan on site assets

version_added: "1.0.0"

description: This module will be used to trigger a scan on selected scan site by user

options:
    hostname:  
        description: Host url/host ip address to connect insightvm instance
        required: true
        type: str
    username:
        description:Username to connect insightvm instance
        required: true
        type: str
    password:
        description: Password to connect insightvm instance.
        required: true
        type: str
    scan_name:
        description: This is the scan name that user will pass 
        required: true
        type: str
    scan_engine_type:
        description: This is the scan engine to trigger a scan
        required: true
        type: str
    scan_site:
        description: This is the scan site on which scan will be triggered
        required: true
        type: str
    scan_template:
        description: This is the scan template used to trigger a scan
        required: true
        type: str
    site_assets:
        description: This is the scan assets list which will be scanned
        required: false
        type: list
    

author:
   - GS Lab (@idmsubs)
'''

EXAMPLES = r'''
 - name: Launch a scan on site assets
   r7_insightvm_scan: 
    hostname: "https://rapid7_insightvm:3780:
    username: "admin"
    password: "admin"
    scan_name: "Discovery-Scan"
    scan_engine_type: "Local-Scan-Engine"
    scan_site: "DC-Site-1"
    scan_template: "Discovery"
    scan_assets:
     - "asset_ip1"
     - "asset_ip2"
    register: output

  - debug:
        msg : "{{output}}"
'''

from ansible.module_utils.basic import *
import json
import requests
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common_utils import get_entity_id
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



class TriggerScan(object):
    def __init__(self,data):
        
        self.scan_name = data.params['scan_name']
        self.scan_engine_type = data.params['scan_engine_type']
        self.scan_site = data.params['scan_site']
        self.scan_template = data.params['scan_template']
        self.scan_assets = data.params['scan_assets']
        self.hostname = data.params['hostname']
        self.username = data.params['username']
        self.password = data.params['password']
        self.action = data.params['action']

    def check_action(self,module):
        if self.action == "create":
            result = self.launch_scan(module)
            return result

    def launch_scan(self,client):
        try:
            
            #get scan engine id
            url1 = self.hostname + "/api/3/scan_engines"
            scan_engine_type_id = get_entity_id(url=url1,module=client,method="GET",payload=self.scan_engine_type)
            if scan_engine_type_id:
                # get scan site id
                url2 = self.hostname + "/api/3/sites"
                scan_site_id = get_entity_id(url=url2,module=client, method="GET",payload=self.scan_site)
                if scan_site_id:
                    # get scan template id
                    url3 = self.hostname + "/api/3/scan_templates"
                    scan_template_id = get_entity_id(url=url3,module=client,method="GET",payload=self.scan_template)
           
            # launch scan
            parameters = {
                "engineId": scan_engine_type_id,
                "hosts": self.scan_assets,
                "name": self.scan_name,
                "templateId": scan_template_id
            }
            
            scan_site_id = str(scan_site_id)
            url4 = self.hostname + "/api/3/sites/"+ scan_site_id + "/scans"
            response = requests.post(url= url4,auth=(self.username,self.password),json= parameters,verify=False,headers={'Content-Type':'application/json'})
            parsed_response = json.loads(response.content)
            
            if response.status_code !=201:
                client.fail_json("Failed to trigger a scan,"+parsed_response['message'],changed=False)
                
            else:
                return parsed_response
            
        except Exception as e:
           client.fail_json("Failed to trigger a scan"+str(e),changed=False)

def main():
 
 
 arguments_spec = dict(
    action=dict(required=True,type="str"),
    hostname= dict(required= True, type= "str"),     
    username= dict(required= True, type= "str"),
    password= dict (required= True, type= "str"),
    scan_name= dict(required= False, type= "str"),
    scan_engine_type= dict(required= False, type= "str"),
    scan_site= dict(required= False, type= "str"),
    scan_template= dict(required= False, type= "str"),
    scan_assets= dict(required= False, type= "list")
 )
 try:
    module = AnsibleModule(argument_spec=arguments_spec,supports_check_mode=False,
    required_if=[["action","create",["scan_name","scan_engine_type","scan_site","scan_template","scan_assets"]]])
    returnMessage = TriggerScan(module)
    get_action_result = returnMessage.check_action(module)
    
     
    module.exit_json(msg=get_action_result,changed=True)
   
 except Exception as e:
    module.fail_json(msg=get_action_result,changed=False)

if __name__ == "__main__":
    main()
