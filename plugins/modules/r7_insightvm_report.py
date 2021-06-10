#/usr/bin/python

ANSIBLE_METADATA = {
    "metadata_version": "1.2",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r'''
module: r7_insightvm_report

short_description: Module to generate custom sql query report for a given scan

version_added: "1.0.0"

description: This module will be used to generate custom report using sql queries for a given scan and site

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
    report_name:
        description: This is the report name used to generate one
        required: true
        type: str
    format:
        description: Output Format of report
        required: true
        type: str
    query:
       description: SQL query used to filter the contents
       required: true
       type: str
    site_scope:
       description: Scope will consist of Scan name and Site name for which the report has to be generated
       required: true
       type: dict
    path:
       description: Location to store the downloaded report
       required: true
       type: str
    severity:
        description: The vulnerability severities to include in the report
        required: false
        type:str
    status:
       description: The vulnerability statuses to include in the report
       required: false
       type:str
    version:
       description: The version of the report Data Model to report against. Only used when the format is "sql-query"
       required:true
       type:str

 author:
   - Aishwarya Bhosale (@aishwarya128)
        
'''
EXAMPLES = r'''
- name: Generate scan report
  r7_insightvm_report:
    hostname: "https://rapid7_insightvm:3780"
    username: "admin"
    password: "password"
    report_name: "Full-Audit-Report"
    format: "sql-query"
    query: "SELECT * FROM fact_asset WHERE vulnerabilities > 0"
    site_scope: "{"site":"DC-Site-1","scan":"Full-Audit Scan"}
    path: "/location_to_download_report"
    severity: "critical"
    register: response

- debug:
    msg: "{{response}}"
'''

from locale import NOEXPR
from os import error
from ansible.module_utils.basic import *
import json
import requests
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common_utils import get_connection
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class GenerateReport(object):
    def __init__(self,client):
       self.hostname,self.username,self.password = get_connection(client)
       self.report_name = client.params['report_name']
       self.site_scope = client.params['site_scope']
       self.format = client.params['format']
       self.query = client.params['query']
       self.severity = client.params['severity']
       self.status= client.params['status']
       self.path = client.params['path']
       self.version = client.params['version']
       self.action = client.params['action']
    
    def check_action(self,client):
        if self.action == "download":
            scan_id,site_id = self.get_entity_id(client)
            if scan_id and site_id:
                response = self.configure_report(client,scan_id,site_id)
                return response

    def get_entity_id(self,client):
        try:
            site_id = None
            scan_id = None
       #get username passed entity ids
            url1 = self.hostname + "/api/3/sites"
      
            sites_response = requests.get(url=url1,auth=(self.username,self.password),headers={"Content-Type":"application/json"},verify=False)
            
            sites_response = json.loads(sites_response.content)
        
            for item1 in sites_response['resources']:
                if item1['name'] == self.site_scope['site']: 
                    site_id = item1['id']
                    break
    
            if site_id:
                site_id = str(site_id)
                url2 = self.hostname + "/api/3/sites/"+ site_id +"/scans?size=10000"
                scans_response = requests.get(url=url2,auth=(self.username,self.password),headers={"Content-Type":"application/json"},verify=False)
                scans_response = json.loads(scans_response.content)
                for item2 in scans_response['resources']:
                    if item2['scanName'] == self.site_scope['scan']: 
                        scan_id = item2['id']
                        print("scan id",scan_id)
                        break
            
            else:
                client.fail_json("Failed to get resource id for site name "+self.site_scope['site'],changed=False)
            
            if scan_id == None:
                client.fail_json("Failed to get resource id for scan name "+self.site_scope['scan'],changed=False)
            else: 
             return scan_id,site_id
        
        except Exception as e: 
            client.fail_json(msg="Failed to get resource ids {}".format(str(e)))

    def configure_report(self,client,scan_id,site_id):
      try:
        time_date = time.strftime("%Y_%m_%d-%H:%M:%S")
        self.report_name= self.report_name+"_"+time_date
        self.site_scope={
            "site": site_id,
            "scan": scan_id
        }
        url1 = self.hostname + "/api/3/reports"
        parameters = {
            "filters": {
                "severity": self.severity,
                "statuses": self.status
            },
            "format": self.format,
            "language": "en-US",
            "name": self.report_name,
            "query": self.query,
            "scope": self.site_scope,
            "timezone": "Asia/Calcutta",
            "version": self.version
            }
      
        #configure report
        response1= requests.post(url=url1,auth=(self.username,self.password),json=parameters,headers={'Content-Type':'application/json'},verify=False)
        parsed_response1 = json.loads(response1.content)
        configured_id = parsed_response1['id']
        print(configured_id)

        #generate report
        if configured_id:
            configured_id = str(configured_id)
            url2= self.hostname + "/api/3/reports/"+ configured_id +"/generate"
            response2 = requests.post(url = url2,auth=(self.username,self.password),headers={'Content-Type':'application/json'},verify=False)
            parsed_response2 = json.loads(response2.content)
            generated_id = parsed_response2['id']
            if generated_id:
                #delay for 2mins for report to get generated
                print("Delaying code execution by 2 minutes as report generation takes some time.")
                time.sleep(120)
                
                #download report
                generated_id = str(generated_id)
                print(generated_id)
                url4= self.hostname + "/api/3/reports/"+ configured_id +"/history/"+ generated_id +"/output"
                response3 = requests.get(url=url4,auth=(self.username,self.password),headers={'Content-Type':'application/json'},verify=False) 
            
                if response3.status_code != 200:
                    client.fail_json(msg="Failed to download the report",changed=False)
                else:
                    #write report contents to a file
                    file = self.path+"/"+self.report_name+".csv"
                
                    f = open(file,"w")
                    f.write(response3.text) 
                    f.close()

                    response4 = response3.content.decode()
                    return response4
            else:
                client.fail_json(msg="Failed to generate the configured report"+parsed_response2["message"],changed=False)

        else:
          client.fail_json(msg= "Failed to configure report"+parsed_response1['message'],changed=False)
      except Exception as e:
        client.fail_json(msg="Failed to generate report for given scan details {}".format(str(e),changed=False))   
    
        
def main():

    arguments_spec=dict(
        action=dict(required= True, type= "str"),  
        hostname= dict(required= True, type= "str"),     
        username= dict(required= True, type= "str"),
        password= dict (required= True, type= "str"),
        report_name= dict(required= False, type= "str"),   
        format=dict(required= False, type= "str"),  
        query=dict(required= False, type= "str"),  
        site_scope=dict(required= False, type= "dict"),
        status=dict(required=False,type="list",choices=["vulnerable" ,"vulnerable-version" ,"potentially-vulnerable" ,"vulnerable-and-validate"],default=['vulnerable']),
        severity=dict(required=False,type="str",choices=["all","critical","critical-and-severe" ],default="critical"),
        version=dict(required=False,type="str",default="2.3.0"),
        path=dict(required=False,type="str")

    )
    try:
        module = AnsibleModule(argument_spec=arguments_spec,supports_check_mode=False,required_if=[["action","download",["report_name","format","query","site_scope","status","severity","version","path"]]])
        cls_obj = GenerateReport(module)
        response = None
        response = cls_obj.check_action(module)
        
        module.exit_json(meta=response,changed=True)
    
    except Exception as e:
       module.fail_json(msg=str(e),changed=False)



if __name__ == '__main__':
    main()
    