# consul_acl

consul_acl allows to maintain desired Consul's ACL set state specified in input file by -f command switch.
Input file must follow JSON format and certain [structure](consul_acl.json). Server's address and master token can be specified by -a and -t switches.
This can be used with configuration management tools like Chef or Ansible that still unable to operate on new non-legacy ACL.
Consul must operate in [new non-legacy ACL mode](https://github.com/hashicorp/consul/blob/master/CHANGELOG.md#140-november-14-2018) in order to consul_acl operate right.

Control tokens 'Master Token', 'Anonymous Token' and policy 'global-management' are skipped.

Master token can also be passed through CONSUL_HTTP_TOKEN environment variable.

```shell
$ ./consul_acl 
You must specify file in JSON format
Maintain Consul's ACL in required state, described in JSON file specified by -f parameter
Version 0.0.5
Usage: ./consul_acl -f <file> [-d]
  -a string
    	Consul server address (default "localhost")
  -d	Tune on verbose output
  -f string
    	JSON file name with Consul ACL set
  -t string
    	ACL agent token

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

Checking again:
```shell
$ ./consul_acl -f consul_acl.json -t master-token -a vm-centos
$
```
