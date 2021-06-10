# Ansible Modules for Rapid7 InsightVM Scan Launch and Report Generation 
[Ansible-Galaxy collections](https://github.com/GSLabDev/ansible-collection-rapid7.git)
repository to create a scan and generate report.

## Installation

For the module to be used you need to have installed [requests](https://github.com/davidban77/gns3fy) library.

```
pip install requests
```

This collections is packaged under ansible-galaxy, so to install it you need to hit following command

```
ansible-galaxy collection install rapid7_insightvm
```

## Features

- Create a scan on assets using Rapid7 InsightVM.
- Generate custom sql query reports for any scans performed

## Modules

These are the modules provided with this collection:
- `r7_insightvm_scan`: Create a scan of assets on a scan site
- `r7_insightvm_report`: Generate a scan report using custom sql query

## Arguments for report generation:

| Parameter        | Type/Required |  Description                                              |
| -----------------|:-------------:| --------------------------------------------------------  |
| action           | str           |  Action name "download" to download a scan report         |
|                  | required:true |                                                           |
|                  |               |                                                           |
| hostname         | str           |  Host url/host ip address to connect insightvm instance   |
|                  | requried:true |                                                           |
|                  |               |                                                           |
| username         | str           |  Username to connect insightvm instance                   |
|                  | requried:true |                                                           |
|                  |               |                                                           |
| password         | str           |  Password to connect insightvm instance                   |
|                  | requried:true |                                                           |
|                  |               |                                                           |
| report_name      | str           |  This is the report name used to generate one             |
|                  | required:true |                                                           |
|                  |               |                                                           |
| format           | str           |  Output format of report                                  |
|                  | required:true |                                                           |
|                  |               |                                                           |
| query            | str           |  SQL query used to filter the contents                    |
|                  | required:true |                                                           |
|                  |               |                                                           |
| site_scope       | dict          | Scope will consist of Scan name and Site name for which   |
|                  | required:true | report has to be generated                                |
|                  |               |                                                           |
| path             | str           | Location to store the downloaded report                   |
|                  | required:true |                                                           |
|                  |               |                                                           |
| severity         | str           | The vulnerability severities to include in the report     |
|                  | required:false|                                                           |
|                  |               |                                                           |
| status           | str           | The vulnerability statuses to include in the report       |
|                  | required:false|                                                           |
|                  |               |                                                           |
| version          | str           |  The version of the report Data Model to report against.  |
|                  | required:true |  Only used when the format is "sql-quqey"                 |


## Arguments to create a scan on site assets:

| Parameter        | Type/Required | Description                                              |
| -----------------|:-------------:| -------------------------------------------------------- |
| action           | str           | Action name "create" to launch a scan on site assets     |
|                  | required:true |                                                          |
|                  |               |                                                          |
| scan_name        | str           | This is the name that user will pass                     | 
|                  | required:true |                                                          |
| scan_engine_type | str           | This is the scan engine to trigger a scan                | 
|                  | required:true |                                                          |
| scan_site        | str           | This is the scan site on which scan will be triggered    |
|                  | required:true |                                                          |
| scan_template    | str           | This is the scan template used to trigger a scan         |
|                  | required:true |                                                          |
|  site_assets     | list          | This is the scan assets list which will be scanned       |
|                  | required:false|                                                          |

## Examples:

Here are some examples of how to use the module.

```yaml
---
- hosts: localhost
  # Call the collections to use the respective modules
  collections:
    - idmsubs.rapid7_insightvm
  tasks:
     - name: Launch a scan on site assets
       r7_insightvm_scan: 
        action: "create"
        hostname: "{{rapid7_host}}"
        username: "{{rapid7_user}}"
        password: "{{rapid7_password}}"
        scan_name: "{{scan_name}}"
        scan_engine_type: "{{rapid7_scan_engine}}"
        scan_site: "{{scan_site_name}}"
        scan_template: "{{scan_template}}"
        scan_assets:
          - "{{asset_ip1}}"
          - "{{asset_ip2}}"
       register: output

     - debug:
         msg : "{{output}}"
```

```yaml
---
- hosts: localhost
  # Call the collections to use the respective modules
  collections:
    - idmsubs.rapid7_insightvm
  tasks: 
    - name: Generate scan report
      r7_insightvm_report:
        action: "download"
        hostname: "{{rapid7_host}}"
        username: "{{rapid7_user}}"
        password: "{{rapid7_password}}"
        report_name: "{{report_name}}"
        format: "{{report_format}}"
        query: "{{sql_query}}"
        site_scope: "{{scope}}"
        path: "{{path}}"
        severity: "{{severity}}"
      register: response

    - debug:
        msg: "{{response}}"
```


Alternative way

```yaml
---
- hosts: localhost
  tasks:
    - name: Launch a scan on site assets on scan sites
      idmsubs.rapid7_insightvm.r7_insightvm_scan:
       action: "create"
       hostname: "{{rapid7_host}}"
       username: "{{rapid7_user}}"
       password: "{{rapid7_password}}"
       scan_name: "{{scan_name}}"
       scan_engine_type: "{{rapid7_scan_engine}}"
       scan_site: "{{scan_site_name}}"
       scan_template: "{{scan_template}}"
       scan_assets:
        - "{{asset_ip1}}"
        - "{{asset_ip2}}"
      register: output

    - debug:
        msg : "{{output}}"
```
```yaml
---
- hosts: localhost
  tasks:
    - name: To generate a scan report
      idmsubs.rapid7_insightvm.r7_insightvm_report:
       action: "download"
       hostname: "{{rapid7_host}}"
       username: "{{rapid7_user}}"
       password: "{{rapid7_password}}"
       report_name: "{{report_name}}"
       format: "{{format}}"
       query: "{{query}}"
       site_scope: "{{site_scope}}" 
       path: "{{path}}"
       severity: "{{severity}}"
      register: output

    - debug:
        msg : "{{output}}"
```

