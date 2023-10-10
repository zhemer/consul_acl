# consul_acl

consul_acl allows to maintain the desired Consul's ACL state specified in the input file by -f command switch.
Input file must follow JSON format and certain [structure](consul_acl.json). Server's address and master token can be specified by -a and -t switches.
This can be used with configuration management tools like Chef or Ansible that are still unable to operate on new non-legacy ACL.
Consul must operate in [new non-legacy ACL mode](https://github.com/hashicorp/consul/blob/master/CHANGELOG.md#140-november-14-2018) in order to consul_acl operate right.\
Control tokens 'Master Token', 'Anonymous Token' and policy 'global-management' are skipped.\
Master token can also be passed through CONSUL_HTTP_TOKEN environment variable.\
Token scope - global or local - can be set ONLY during token creation, Consul API doesn't allow to toggle it after that - token must be re-created with appropriate locality.
Current Consul' ACL set can be dumped to terminal (file) in JSON format appropriate for input file specified by -f switch. And as configuration dumped unformatted, better to format it by jq:
```shell

$ ./consul_acl -a vm-centos -t $t -d|jq
{
  "Policy": [
    {
      "Name": "pol-nginx",
      "Rules": "agent \"\" {policy=\"write\"}\nsession \"\" {policy=\"write\"}"
    },
    {
      "Name": "pol-octopus",
      "Rules": "key \"octopus/\" {policy = \"write\"}"
    },
    {
      "Name": "pol-dc",
      "Rules": "node \"\" {policy=\"read\"}",
      "Dc": [
        "dc1"
      ]
    }
  ],
  "Role": [
    {
      "Name": "role-nginx",
      "Policies": [
        "pol-nginx"
      ]
    },
    {
      "Descr": "Some Descr",
      "Name": "role1",
      "Policies": [
        "pol-octopus",
        "pol-vault"
      ]
    }
  ],
  "Token": [
    {
      "Descr": "kube",
      "Policies": [
        "pol-kube"
      ],
      "Roles": [
        "role1"
      ],
      "AccessorID": "a58ce363-646b-4a6b-bd93-26a038170630",
      "Local": true
    },
    {
      "Descr": "nginx",
      "Policies": [
        "pol-nginx"
      ],
      "AccessorID": "01496e9c-ba84-4d1f-a2e0-747c415f6f8d"
    },
    {
      "Descr": "octopus",
      "Policies": [
        "pol-octopus"
      ],
      "AccessorID": "70422b37-4526-4513-87c4-04be72540dc0"
    }
  ]
}
```

Help screen:
```shell
$ ./consul_acl 
You must specify one of mandatory switch: '-f' or '-d'
Maintains Consul's ACL in required state, described in JSON file specified by -f switch.
Consul ACL can be saved (dumped) to terminal beforehand using -d switch.
Version 0.0.8
Usage: ./consul_acl [-f <file> | -d] [-a address] [-t token] [-d]
  -a string
    	Consul server address (default "localhost")
  -d	Dump ACL
  -f string
    	JSON file name with Consul ACL set
  -t string
    	ACL agent token
  -v	Tune on verbose output

```

Setting Consul's ACL:
```shell
$ ./consul_acl -f consul_acl.json -a vm-centos -t $t
Removed policy "policy-octopus"
Removed policy "policy-vault"
Created policy "pol-nginx"
Created policy "pol-vault"
Created policy "pol-octopus"
Created policy "pol-kube"
Updated role "role-octopus": Policies: 'policy-octopus' => 'pol-octopus'
Updated role "role1": Policies: 'policy-octopus,policy-vault' => 'pol-octopus,pol-vault'
Created role "role-nginx"
Removed token "505b8379-bc33-402c-8d0d-e026ac206da9"
Removed token "fbb42a97-42eb-44f0-b2de-0e3126c63cce"
Removed token "629e6ca8-971c-470b-badd-80babdd1a7df"
Created token {"nginx" ["pol-nginx"] [] "70422b37-4526-4513-87c4-04be72540dc0"}
Created token {"kube" ["pol-kube"] ["role1"] "a58ce363-646b-4a6b-bd93-26a038170619"}
Created token {"vault" ["pol-vault"] [] "f6774eb5-17df-45af-818b-4f7742defe69"}
```
