# consul_acl

consul_acl allows to maintain desired Consul's ACL set state specified in input file by -f command switch.
Input file must follow JSON format and certain [structure](acl.json).

```console
root @ vm-centos : /mnt/gitast/szhemerdeev/consul_acl   2020-10-26 19:05:44    %Cpu(s):0.0us 6.2sy 0.0ni 93.8id 0.0wa 0.0hi 0.0si 0.0st 
# ./consul_acl
You must specify file in JSON format
Maintain Consul's ACL in required state, described in JSON file specified by -f parameter
Version 0.0.1
Usage: ./consul_acl -f <file> [-d]
  -d	Tune on verbose output
  -f string
    	string - JSON file name with Consul ACL set

```

Next excerpt shows the program's run just after first Consul startup:
```console
root @ vm-centos : /mnt/gitast/szhemerdeev/consul_acl   2020-10-26 19:05:43    %Cpu(s):5.9us 5.9sy 0.0ni 88.2id 0.0wa 0.0hi 0.0si 0.0st 
# ./consul_acl -f acl.json;echo $?
Created policy "policy-vault"
Created policy "policy-octopus"
Created token {"vault" "" "policy-vault" "9e6acf6a-c74b-41eb-8843-0e3ddad0a855"}
Created token {"octopus" "" "policy-octopus" "aafb482d-3524-4a87-b7ca-cfe3687ee4e7"
```
