# consul_acl

consul_acl allows to maintain desired Consul's ACL set state specified in input file by -f command switch.
Input file must follow JSON format and certain [structure](consul_acl.json). Server's address and master token can be specified by -a and -t switches.
This can be used with configuration management tools like Chef or Ansible that still unable to operate on new non-legacy ACL.
Consul must operate in [new non-legacy ACL mode](https://github.com/hashicorp/consul/blob/master/CHANGELOG.md#140-november-14-2018) in order to consul_acl operate right.\
Control tokens 'Master Token', 'Anonymous Token' and policy 'global-management' are skipped.\
Master token can also be passed through CONSUL_HTTP_TOKEN environment variable.\
Token scope - global or local - can be set ONLY during token creation, Consul API doesn't allow to toggle it after that - token must be re-created with appropriate locality.
Current Consul' ACL set can be dumped to terminal (file) in JSON format appropriate for input file specified by -f switch. And as configuration dumped unformatted, better to format it by jq:
```shell

$ ./consul_acl -t $t -d|jq
{
  "Policies": {
    "policy-dc": {
      "Description": "policy Description",
      "Rules": "node \"\" {policy=\"read\"}",
      "Dc": [
        "dc1"
      ]
    },
    "pol-kube": {
      "Rules": "check \"\" {policy=\"write\"}\nservice \"\" {policy=\"write\"}\nkey \"consul-alerts/\" {policy=\"write\"}\nkeyring = \"write\""
    },
    "pol-nginx": {
      "Rules": "agent \"\" {policy=\"write\"}\nsession \"\" {policy=\"write\"}"
    },
    "pol-octopus": {
      "Rules": "key \"octopus/\" {policy = \"write\"}"
    },
    "pol-vault": {
      "Description": "Some Descr",
      "Rules": "key \"vault/\" {policy=\"write\"}\nnode \"\" {policy = \"write\"}\nservice \"vault\" {policy=\"write\"}"
    }
  },
  "Roles": {
    "role-nginx": {
      "Policies": [
        "pol-nginx"
      ]
    },
    "role-octopus": {
      "Policies": [
        "pol-octopus",
        "policy-dc"
      ]
    },
    "role1": {
      "Description": "Some Descr",
      "Policies": [
        "pol-vault",
        "pol-octopus"
      ]
    }
  },
  "Tokens": {
    "01496e9c-ba84-4d1f-a2e0-747c415f6f8d": {
      "Description": "nginx",
      "Policies": [
        "pol-nginx"
      ],
      "Roles": [
        "role-nginx",
        "role-octopus"
      ]
    },
    "70422b37-4526-4513-87c4-04be72540dc0": {
      "Description": "octopus",
      "Policies": [
        "pol-octopus",
        "pol-nginx"
      ]
    },
    "a58ce363-646b-4a6b-bd93-26a038170630": {
      "Description": "kube",
      "Policies": [
        "pol-kube"
      ],
      "Roles": [
        "role1"
      ],
      "Local": true
    },
    "f6774eb5-17df-45af-818b-4f7742defe69": {
      "Description": "vault",
      "Policies": [
        "pol-vault",
        "pol-kube",
        "pol-nginx"

      ]
    }
  }
}
```

Help screen:
```shell
$ ./consul_acl 
You must specify one of mandatory switch: '-f' or '-d'
Maintains Consul ACL in required state, described in JSON file specified by -f switch.
Consul ACL can be saved (dumped) to terminal beforehand using -d switch.
Version 0.0.9
Usage: ./consul_acl [-f <file> | -d] [-a address] [-t token] [-d]
  -a string
    	Consul server address (default "localhost")
  -d	Dump current ACL
  -f string
    	JSON file name with Consul ACL set
  -p string
    	Consul server port (default "8500")
  -t string
    	Consul agent token
  -v	Enable verbose output
```

Restoring Consul's ACL:
```shell
$ ./consul_acl -f consul_acl.json -t $t
2024/06/03 23:01:19 acl.go:159: Created policy "policy-dc"
2024/06/03 23:01:19 acl.go:159: Created policy "pol-kube"
2024/06/03 23:01:19 acl.go:159: Created policy "pol-nginx"
2024/06/03 23:01:19 acl.go:159: Created policy "pol-octopus"
2024/06/03 23:01:19 acl.go:159: Created policy "pol-vault"
2024/06/03 23:01:19 acl.go:229: Created role "role-nginx"
2024/06/03 23:01:19 acl.go:229: Created role "role-octopus"
2024/06/03 23:01:19 acl.go:229: Created role "role1"
2024/06/03 23:01:19 acl.go:323: Created token {Description:nginx Policies:[pol-nginx] Roles:[role-nginx role-octopus] Local:false}
2024/06/03 23:01:19 acl.go:323: Created token {Description:octopus Policies:[pol-octopus pol-nginx] Roles:[] Local:false}
2024/06/03 23:01:19 acl.go:323: Created token {Description:kube Policies:[pol-kube] Roles:[role1] Local:true}
2024/06/03 23:01:19 acl.go:323: Created token {Description:vault Policies:[pol-vault pol-kube pol-nginx] Roles:[] Local:false}
```
