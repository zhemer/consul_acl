# consul_acl

consul_acl allows to maintain desired Consul's ACL set state specified in input file by -f command switch.
Input file must follow JSON format and certain [structure](consul_acl.json). Server's address and master token can be specified by -a and -t switches.
This can be used with configuration management tools like Chef or Ansible that still unable to operate on new non-legacy ACL.
Consul must operate in [new non-legacy ACL mode](https://github.com/hashicorp/consul/blob/master/CHANGELOG.md#140-november-14-2018) in order to consul_acl operate right.

```shell
$ ./consul_acl 
You must specify file in JSON format
Maintain Consul's ACL in required state, described in JSON file specified by -f parameter
Version 0.0.4
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
$ ./consul_acl -f consul_acl.json -t master-token -a vm-centos
Created policy "policy-default-client"
Created role "role1"
Updated token "octopus"("aafb482d-3524-4a87-b7ca-cfe3687ee4e7"): "Policies: '' => 'policy-octopus'"
Created token {"Default client token" ["policy-octopus"] ["role1"] "8e576c87-ce71-436c-925a-0e24e0b11c52"}
```

Checking again:
```shell
$ ./consul_acl -f consul_acl.json -t master-token -a vm-centos
$
```
