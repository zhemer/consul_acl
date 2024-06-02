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
	"strings"
	"time"

	"github.com/hashicorp/consul/api"
)

const (
	version        = "0.0.9"
	sKip           = "skip"
	anonymousToken = "anonymous"
	masterPolicy   = "global-management"
)

type Policy struct {
	Description string   `json:"Description,omitempty"`
	Rules       string   `json:"Rules"`
	Dc          []string `json:"Dc,omitempty"`
}
type Role struct {
	Description string   `json:"Description,omitempty"`
	Policies    []string `json:"Policies,omitempty"`
}
type Token struct {
	Description string   `json:"Description,omitempty"`
	Policies    []string `json:"Policies,omitempty"`
	Roles       []string `json:"Roles,omitempty"`
	Local       bool     `json:"Local,omitempty"`
}
type Acl struct {
	Policies map[string]Policy // Policy name is a key
	Roles    map[string]Role   `json:"Roles,omitempty"` // Role name is a key
	Tokens   map[string]Token  // SecretID is a key
}

type ConsulAcl struct {
	policyList []*api.ACLPolicy
	roleList   []*api.ACLRole
	tokenList  []*api.ACLToken
}

var isDebug = flag.Bool("v", false, "Enable verbose output")

func main() {
	var fileAcl = flag.String("f", "", "JSON file name with Consul ACL set")
	var serverAddress = flag.String("a", "localhost", "Consul server address")
	var serverPort = flag.String("p", "8500", "Consul server port")
	var agentTokenParameter = flag.String("t", "", "Consul agent token")
	var isDump = flag.Bool("d", false, "Dump current ACL")
	var consulAcl ConsulAcl

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
	acl, err := ConsulConnect(agentToken, *serverAddress, *serverPort)
	if err != nil {
		log.Fatalf("Error: ConsulConnect: %v", err)
	} else if acl == nil {
		log.Fatalf("Error: ConsulConnect returned an empty ACL")
	}

	// Read whole ACL into consulAcl variable
	if err = consulAcl.GetList(acl, agentToken); err != nil {
		log.Fatalf("Error: GetList: %v", err)
	}

	// Dump ACL as JSON if isDump was specified
	if *isDump {
		if aclJson, err := consulAcl.Dump(); err == nil {
			fmt.Print(aclJson)
			return
		}
		log.Fatalf("Error: Dump: %v", err)
	}

	// Read our ACL from file
	requiredConsulAcl, err := ReadACLFromFile(*fileAcl)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// Compare config and Consul policies
	policyNameToId, err := SyncPolicies(consulAcl, requiredConsulAcl, acl)
	if err != nil {
		log.Fatalf("Error: SyncPolicies: %v", err)
	}

	// Compare config and Consul roles
	roleNameToId, err := SyncRoles(consulAcl, requiredConsulAcl, acl, policyNameToId)
	if err != nil {
		log.Fatalf("Error: SyncRoles: %v", err)
	}

	// Compare config and Consul tokens
	err = SyncTokens(consulAcl, requiredConsulAcl, acl, policyNameToId, roleNameToId, agentToken)
	if err != nil {
		log.Fatalf("Error: SyncTokens: %v", err)
	}
}

// Get ACL from Consul
func (acl *ConsulAcl) GetList(consulAcl *api.ACL, masterToken string) error {
	aclPolicyList, _, err := consulAcl.PolicyList(nil)
	if err != nil {
		return fmt.Errorf("PolicyList: %w", err)
	}
	for _, pol := range aclPolicyList {
		policy, _, err := consulAcl.PolicyRead(pol.ID, nil)
		if err != nil {
			return fmt.Errorf("PolicyRead: %w", err)
		}
		if policy.Name == masterPolicy {
			continue
		}
		acl.policyList = append(acl.policyList, policy)
	}

	aclRoleList, _, err := consulAcl.RoleList(nil)
	if err != nil {
		return fmt.Errorf("RoleList: %w", err)
	}
	for _, role := range aclRoleList {
		role, _, err := consulAcl.RoleRead(role.ID, nil)
		if err != nil {
			return fmt.Errorf("RoleRead: %w", err)
		}
		acl.roleList = append(acl.roleList, role)
	}

	aclTokenList, _, err := consulAcl.TokenList(nil)
	if err != nil {
		return err
	}
	for _, token := range aclTokenList {
		token, _, err := consulAcl.TokenRead(token.AccessorID, nil)
		if err != nil {
			return fmt.Errorf("TokenRead: %w", err)
		}
		if token.SecretID == masterToken || token.SecretID == anonymousToken {
			continue
		}
		acl.tokenList = append(acl.tokenList, token)
	}

	return nil
}

// TODO: make pretty formatted json
func (acl *ConsulAcl) Dump() (string, error) {
	policies := map[string]Policy{}
	roles := map[string]Role{}
	tokens := map[string]Token{}

	for _, policy := range acl.policyList {
		policies[policy.Name] = Policy{
			Description: policy.Description,
			Rules:       policy.Rules,
			Dc:          policy.Datacenters}
	}

	for _, role := range acl.roleList {
		roles[role.Name] = Role{
			Description: role.Description,
			Policies:    ACLLinkToStringList(role.Policies)}
	}

	for _, token := range acl.tokenList {
		tokens[token.SecretID] = Token{
			Description: token.Description,
			Policies:    ACLLinkToStringList(token.Policies),
			Roles:       ACLLinkToStringList(token.Roles),
			Local:       token.Local,
		}
	}

	aclTmp := Acl{Policies: policies, Roles: roles, Tokens: tokens}
	slog.Debug(fmt.Sprintf("aclTmp %+v", aclTmp))
	aclJson, err := json.Marshal(aclTmp)
	if err != nil {
		return "", err
	}
	return string(aclJson), nil
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

// Check Consul policies and make them equal to ours
func SyncPolicies(consulAcl ConsulAcl, ourAcl Acl, acl *api.ACL) (map[string]string, error) {
	policyNameToId := map[string]string{}
	for _, policy := range consulAcl.policyList {
		slog.Debug("policy=%v", policy)
		// Skipping policy marked as "skip" or masterPolicy
		if ourAcl.Policies[policy.Name].Description == sKip || policy.Name == masterPolicy {
			slog.Debug("Skipping policy %q", policy.Name)
			continue
		}

		// Removing unknown policy
		if _, ok := ourAcl.Policies[policy.Name]; !ok {
			if _, err := acl.PolicyDelete(policy.ID, nil); err != nil {
				return nil, fmt.Errorf("PolicyDelete for %v: %w", policy, err)
			}
			log.Printf("Removed policy %q", policy.Name)
			continue
		}

		policyNameToId[policy.Name] = policy.ID
		change := ""

		slog.Debug(fmt.Sprintf("policy Datacenters %q %q %v", policy.Datacenters,
			ourAcl.Policies[policy.Name].Dc, StringsListsCompare(policy.Datacenters, ourAcl.Policies[policy.Name].Dc)))
		// Checking policy datacenter
		if !StringsListsCompare(policy.Datacenters, ourAcl.Policies[policy.Name].Dc) {
			change = "Datacenters: '" + strings.Join(policy.Datacenters, ",") + "' => '" +
				strings.Join(ourAcl.Policies[policy.Name].Dc, ",") + "', "
			policy.Datacenters = ourAcl.Policies[policy.Name].Dc
		}
		// Checking policy description
		if policy.Description != ourAcl.Policies[policy.Name].Description {
			change += "Description: '" + policy.Description + "' => '" + ourAcl.Policies[policy.Name].Description + "', "
			policy.Description = ourAcl.Policies[policy.Name].Description
		}
		if policy.Rules != ourAcl.Policies[policy.Name].Rules {
			change += "Rules: '" + policy.Rules + "' => '" + ourAcl.Policies[policy.Name].Rules + "'"
			policy.Rules = ourAcl.Policies[policy.Name].Rules
		}

		// Updating policy
		if change != "" {
			change = strings.TrimRight(change, ", ")
			_, _, err := acl.PolicyUpdate(policy, nil)
			if err != nil {
				return nil, fmt.Errorf("PolicyUpdate for %v: %w", policy, err)
			}
			log.Printf("Updated policy %q: %s", policy.Name, change)
		}
		delete(ourAcl.Policies, policy.Name)
	}

	// Creating absent policies
	for k, v := range ourAcl.Policies {
		if v.Description == sKip {
			slog.Debug("Skipping policy %q", k)
			continue
		}
		_, _, err := acl.PolicyCreate(&api.ACLPolicy{Name: k, Rules: v.Rules, Description: v.Description, Datacenters: v.Dc}, nil)
		if err != nil {
			return nil, fmt.Errorf("PolicyCreate for %v: %w", v, err)
		}
		log.Printf("Created policy %q", k)
	}
	return policyNameToId, nil
}

// Check Consul roles and make them equal to ours
func SyncRoles(consulAcl ConsulAcl, ourConsulAcl Acl, acl *api.ACL, policyNameToId map[string]string) (map[string]string, error) {
	roleNameToId := map[string]string{}
	for _, role := range consulAcl.roleList {
		slog.Debug(fmt.Sprintf("role=%+v", role))

		// Skipping marked role
		if ourConsulAcl.Roles[role.Name].Description == sKip {
			slog.Debug(fmt.Sprintf("Skipping role %q", role.Name))
			continue
		}

		// Removing unknown role
		if _, ok := ourConsulAcl.Roles[role.Name]; !ok {
			if _, err := acl.RoleDelete(role.ID, nil); err != nil {
				return nil, fmt.Errorf("RoleDelete for %v: %w", role.Name, err)
			}
			log.Printf("Removed role %q", role.Name)
			continue
		}

		roleNameToId[role.Name] = role.ID

		change := ""
		// Checking role's description
		if role.Description != ourConsulAcl.Roles[role.Name].Description {
			change += "Description: '" + role.Description + "' => '" + ourConsulAcl.Roles[role.Name].Description + "', "
			role.Description = ourConsulAcl.Roles[role.Name].Description
		}
		// Creating roles policy list to compare
		var rpl []string
		for _, p := range role.Policies {
			rpl = append(rpl, p.Name)
		}
		if !StringsListsCompare(rpl, ourConsulAcl.Roles[role.Name].Policies) || role.Description != ourConsulAcl.Roles[role.Name].Description {
			change += "Policies: '" + strings.Join(rpl, ",") + "' => '" + strings.Join(ourConsulAcl.Roles[role.Name].Policies, ",") + "'"
			role.Policies = StringMapToACLLinkList(policyNameToId, ourConsulAcl.Roles[role.Name].Policies)
		}
		// Updating role
		if change != "" {
			change = strings.TrimRight(change, ", ")
			_, _, err := acl.RoleUpdate(role, nil)
			if err != nil {
				return nil, fmt.Errorf("RoleUpdatefor for %v: %q", role.Name, err)
			}
			log.Printf("Updated role %q: %s", role.Name, change)
		}
		delete(ourConsulAcl.Roles, role.Name)
	}

	// Creating absent roles
	for k, v := range ourConsulAcl.Roles {
		if v.Description == sKip {
			slog.Debug(fmt.Sprintf("Skipping role %q", k))
			continue
		}
		policyList := StringMapToACLLinkList(policyNameToId, v.Policies)

		if _, _, err := acl.RoleCreate(&api.ACLRole{Name: k, Policies: policyList, Description: v.Description}, nil); err != nil {
			return nil, fmt.Errorf("RoleCreate for %v: %q", k, err)
		}
		log.Printf("Created role %q", k)
	}
	return roleNameToId, nil
}

func SyncTokens(consulAcl ConsulAcl, requiredConsulAcl Acl, acl *api.ACL, policyNameToId map[string]string, roleNameToId map[string]string, agentToken string) error {
	for _, token := range consulAcl.tokenList {
		slog.Debug(fmt.Sprintf("token %+v", token))

		// Skipping marked token
		if requiredConsulAcl.Tokens[token.SecretID].Description == sKip ||
			token.SecretID == agentToken || token.SecretID == anonymousToken {
			slog.Debug(fmt.Sprintf("Skipping token %q (%v)", token.Description, token.SecretID))
			delete(requiredConsulAcl.Tokens, token.SecretID)
			continue
		}

		// Removing unknown and legacy tokens(len(token.Rules)>0)
		legacy := ""
		if len(token.Rules) > 0 {
			legacy = " legacy"
		}
		if _, ok := requiredConsulAcl.Tokens[token.SecretID]; !ok || legacy != "" {
			if _, err := acl.TokenDelete(token.AccessorID, nil); err != nil {
				return fmt.Errorf("TokenDelete%v for %+v: %w", legacy, token, err)
			}
			log.Printf("Removed%v token %q (%+v)", legacy, token.Description, token)
			continue
		}

		change := ""
		// Checking token description
		if token.Description != requiredConsulAcl.Tokens[token.SecretID].Description {
			change = "Description: '" + token.Description + "' => '" + requiredConsulAcl.Tokens[token.SecretID].Description + "', "
			token.Description = requiredConsulAcl.Tokens[token.SecretID].Description

		}
		// Creating tokens policy list to compare
		var tokenPolicyList []string
		for _, p := range token.Policies {
			tokenPolicyList = append(tokenPolicyList, p.Name)
		}
		slog.Debug(fmt.Sprintf("Policies: server: %q file: %q StringsListsCompare: %v", tokenPolicyList,
			requiredConsulAcl.Tokens[token.SecretID].Policies,
			StringsListsCompare(tokenPolicyList, requiredConsulAcl.Tokens[token.SecretID].Policies)))
		// Updating token policy list
		if !StringsListsCompare(tokenPolicyList, requiredConsulAcl.Tokens[token.SecretID].Policies) {
			change += "Policies: '" + strings.Join(tokenPolicyList, ",") + "' => '" +
				strings.Join(requiredConsulAcl.Tokens[token.SecretID].Policies, ",") + "', "
			token.Policies = StringMapToACLLinkList(policyNameToId, requiredConsulAcl.Tokens[token.SecretID].Policies)
		}

		// Creating token  roles list to compare
		var tokeRoleList []string
		for _, p := range token.Roles {
			tokeRoleList = append(tokeRoleList, p.Name)
		}
		slog.Debug(fmt.Sprintf("Roles: server: %q file: %q StringsListsCompare: %v", tokeRoleList,
			requiredConsulAcl.Tokens[token.SecretID].Roles,
			StringsListsCompare(tokeRoleList, requiredConsulAcl.Tokens[token.SecretID].Roles)))
		// Updating token's roles list
		if !StringsListsCompare(tokeRoleList, requiredConsulAcl.Tokens[token.SecretID].Roles) {
			change += "Roles: '" + strings.Join(tokeRoleList, ",") + "' => '" + strings.Join(requiredConsulAcl.Tokens[token.SecretID].Roles, ",") + "'"
			token.Roles = StringMapToACLLinkList(roleNameToId, requiredConsulAcl.Tokens[token.SecretID].Roles)
		}

		// Updating token
		if change != "" {
			change = strings.TrimRight(change, ", ")
			if _, _, err := acl.TokenUpdate(token, nil); err != nil {
				return fmt.Errorf("TokenUpdate for %v: %w", token, err)
			}
			log.Printf("Updated token %q (%q): %q", token.Description, token.SecretID, change)
		}
		delete(requiredConsulAcl.Tokens, token.SecretID)
	}

	// Creating absent tokens
	slog.Debug(fmt.Sprintf("aclTokens %+v", requiredConsulAcl.Tokens))
	for k, v := range requiredConsulAcl.Tokens {
		if k == sKip {
			continue
		}
		policyList := StringMapToACLLinkList(policyNameToId, v.Policies)
		roleList := StringMapToACLLinkList(roleNameToId, v.Roles)
		if _, _, err := acl.TokenCreate(&api.ACLToken{
			SecretID: k, Description: v.Description,
			Policies: policyList, Roles: roleList, Local: v.Local}, nil); err != nil {
			return fmt.Errorf("TokenCreate for %+v: %w", v, err)
		}
		log.Printf("Created token %+v", v)
	}
	return nil
}
