package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"sort"
	"time"

	"github.com/hashicorp/consul/api"
)

const (
	version        = "0.0.9"
	sKip           = "skip"
	anonymousToken = "anonymous"
	masterPolicy   = "global-management"
)

func main() {
	var fileAcl = flag.String("f", "", "JSON file name with Consul ACL set")
	var serverAddress = flag.String("a", "localhost", "Consul server address")
	var serverPort = flag.String("p", "8500", "Consul server port")
	var agentTokenParameter = flag.String("t", "", "Consul agent token")
	var isDump = flag.Bool("d", false, "Dump current ACL")
	var isDebug = flag.Bool("v", false, "Enable verbose output")

	log.SetFlags(log.Lshortfile | log.LstdFlags)
	flag.Usage = func() {
		fmt.Printf(`Maintains Consul ACL in required state, described in JSON file specified by -f switch.
Consul ACL can be saved (dumped) to terminal beforehand using -d switch.
Version %s
`, version)
		fmt.Printf("Usage: %s [-f <file> | -d] [-a address] [-t token] [-d]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *fileAcl == "" && !*isDump || *fileAcl != "" && *isDump {
		fmt.Printf("You must specify one of mandatory switch: '-f' or '-d'\n")
		flag.Usage()
		return
	}

	if *isDebug {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	agentToken := *agentTokenParameter
	if agentToken == "" {
		agentToken = os.Getenv("CONSUL_HTTP_TOKEN")
	}

	// Connect to Consul
	consulAcl, err := ConsulConnect(agentToken, *serverAddress, *serverPort)
	if err != nil {
		log.Fatalf("Error: ConsulConnect: %v", err)
	} else if consulAcl == nil {
		log.Fatalf("Error: ConsulConnect returned an empty ACL")
	}
	dumpAcl := Acl{consulAcl: consulAcl, consulToken: agentToken}

	// Dump ACL as JSON if isDump was specified
	if *isDump {
		if aclJson, err := dumpAcl.Dump(); err == nil {
			fmt.Print(aclJson)
			return
		}
		log.Fatalf("Error: Dump: %v", err)
	}

	// Read our ACL from file
	acl, err := ReadACLFromFile(*fileAcl)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	acl.consulAcl = consulAcl
	acl.consulToken = agentToken

	// Compare config and Consul policies
	policyNameToId, err := acl.SyncPolicies()
	if err != nil {
		log.Fatalf("Error: SyncPolicies: %v", err)
	}

	// Compare config and Consul roles
	roleNameToId, err := acl.SyncRoles(policyNameToId)
	if err != nil {
		log.Fatalf("Error: SyncRoles: %v", err)
	}

	// Compare config and Consul tokens
	err = acl.SyncTokens(policyNameToId, roleNameToId)
	if err != nil {
		log.Fatalf("Error: SyncTokens: %v", err)
	}
}

func StringMapToACLLinkList(stringMap map[string]string, list []string) []*api.ACLLink {
	var links []*api.ACLLink
	for _, s := range list {
		links = append(links, &api.ACLLink{ID: stringMap[s], Name: s})
	}
	return links
}

func StringsListsCompare(a1, a2 []string) bool {
	if len(a1)+len(a2) == 0 {
		return true
	}
	if len(a1) != len(a2) {
		return false
	}
	sort.Strings(a1)
	sort.Strings(a2)
	for i := range a1 {
		if a1[i] != a2[i] {
			return false
		}
	}
	return true
}

func ACLLinkToStringList(aclLink []*api.ACLLink) (list []string) {
	for _, link := range aclLink {
		list = append(list, link.Name)
	}
	return list
}

// Connect to Consul server
func ConsulConnect(token string, address string, port string) (*api.ACL, error) {
	config := api.DefaultConfig()
	config.WaitTime = time.Second * 30
	if token != "" {
		config.Token = token
	}
	config.Address = address + ":" + port

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("NewClient: %w", err)
	}
	return client.ACL(), nil
}

// Read saved ACL from file
func ReadACLFromFile(fileAcl string) (aclList Acl, err error) {
	data, err := os.ReadFile(fileAcl)
	if err != nil {
		return aclList, err
	}
	if !json.Valid(data) {
		return aclList, errors.New(fileAcl + ": invalid JSON format")
	}

	err = json.Unmarshal(data, &aclList)
	if err != nil {
		return aclList, err
	}
	slog.Debug(fmt.Sprintf("aclList %+v", aclList))
	if len(aclList.Policies) == 0 || len(aclList.Tokens) == 0 {
		return aclList, errors.New("no policies or tokens in the input file")
	}
	return aclList, nil
}
