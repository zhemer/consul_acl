package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/hashicorp/consul/api"
	"io/ioutil"
	"log"
	"os"
	"time"
)

const sVer = "0.0.3"

type PolicyS struct {
	Descr string `json:"Descr"`
	Name  string `json:"Name"`
	Rules string `json:"Rules"`
}

type ConsulAcl1 struct {
	Policy []PolicyS
	Role   []struct {
		Descr    string   `json:"Descr"`
		Name     string   `json:"Name"`
		Policies []string `json:"Policies"`
	} `json:"role"`
	Token []struct {
		Descr    string   `json:"Descr"`
		Name     string   `json:"Name"`
		Policies []string `json:"Policies"`
		Roles    []string `json:"Roles"`
		Token    string   `json:"Token"`
	} `json:"token"`
}

type ConsulAcl struct {
	Policy []struct {
		Descr string `json:"Descr"`
		Name  string `json:"Name"`
		Rules string `json:"Rules"`
	} `json:"policy"`
	Role []struct {
		Descr    string   `json:"Descr"`
		Name     string   `json:"Name"`
		Policies []string `json:"Policies"`
	} `json:"role"`
	Token []struct {
		Descr    string   `json:"Descr"`
		Name     string   `json:"Name"`
		Policies []string `json:"Policies"`
		Roles    []string `json:"Roles"`
		Token    string   `json:"Token"`
	} `json:"token"`
}

var (
	sFileAcl = flag.String("f", "", "string - JSON file name with Consul ACL set")
	sToken   = flag.String("t", "", "ACL agent token")
	iDebug   = flag.Bool("d", false, "Tune on verbose output")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Maintain Consul's ACL in required state, described in JSON file specified by -f parameter\nVersion %s\n", sVer)
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s -f <file> [-d]\n", os.Args[0])
		flag.PrintDefaults()
		// fmt.Fprintf(flag.CommandLine.Output(), "\n"+sHelp)
	}
	flag.Parse()
	if *sFileAcl == "" {
		fmt.Printf("You must specify file in JSON format\n")
		flag.Usage()
		return
	}

	// Read ACL JSON list
	data, err := ioutil.ReadFile(*sFileAcl)
	if err != nil {
		log.Fatal(err)
	}
	if !json.Valid(data) {
		log.Fatal(*sFileAcl + ": invalid JSON format\n")
	}

	var aclList ConsulAcl1
	err = json.Unmarshal([]byte(data), &aclList)
	if err != nil {
		log.Fatal(err)
	}

	Log("aclList %v\n\n", aclList)

	// Creating AA from parsed JSON
	aclPol := map[string]PolicyS{}
	// Log("Policy %+v\n", aclList["policy"])
	for _, v := range aclList.Policy {
		Log("--- %q\n", v)
		aclPol[v.Name] = v
	}
	Log("== aclPol %q\n\n", aclPol)

	// ==============================================

	// Get a new client
	config := api.DefaultConfig()
	time30s, _ := time.ParseDuration("30s")
	config.WaitTime = time30s
	if *sToken != "" {
		config.Token = *sToken
	}

	// config.Address = "192.168.122.3:8500"
	config.Address = "vm-centos:8500"
	client, err := api.NewClient(config)
	if err != nil {
		Log("config %v\n", config)
		panic(err)
	}

	acl := client.ACL()

	// ===========================================================
	// Policy
	// ===========================================================
	aclPol1 := map[string]string{}
	aclPolList, wm, err := acl.PolicyList(nil)
	if err != nil {
		log.Fatal(err)
	}
	Log("==== acl.PolicyList %v %v %v\n", aclPolList, wm, err)
	for _, pol := range aclPolList {
		policy, _, err := acl.PolicyRead(pol.ID, nil)
		Log("== acl.PolicyList(pol.ID=%v) aclPolicy=%v err=%v\n\n", pol.ID, policy, err)
		if aclPol[pol.Name].Descr == "skip" {
			continue
		}
		if aclPol[pol.Name].Name == "" {
			_, err := acl.PolicyDelete(pol.ID, nil)
			if err != nil {
				log.Fatalf("%v: %q\n", err, pol)
			} else {
				fmt.Printf("Removed policy %q\n", pol.Name)
			}
			continue
		}
		aclPol1[pol.Name] = policy.Name
		if policy.Rules != aclPol[pol.Name].Rules || policy.Description != aclPol[pol.Name].Descr {
			policy.Rules = aclPol[pol.Name].Rules
			policy.Description = aclPol[pol.Name].Descr
			_, _, err := acl.PolicyUpdate(policy, nil)
			if err != nil {
				log.Fatal(err)
				log.Fatalf("%v: %q\n", err, pol)
			} else {
				fmt.Printf("Updated policy %q\n", pol.Name)
			}
		}

	}
	for k, v := range aclPol {
		Log("=== %q %q\n", k, v)
		if v.Descr == "skip" {
			continue
		}
		if aclPol1[k] == "" {
			_, _, err := acl.PolicyCreate(&api.ACLPolicy{Name: k, Rules: v.Rules}, nil)
			if err != nil {
				log.Fatal(err)
				log.Fatalf("%v: %q\n", err, v)
			} else {
				fmt.Printf("Created policy %q\n", k)
			}

		}
	}

}

func Log(format string, a ...interface{}) {
	if *iDebug == true {
		fmt.Printf(format, a...)
	}
}
