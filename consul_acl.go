package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/hashicorp/consul/api"
	"io/ioutil"
	"log"
	"os"
	// "reflect"
	"sort"
	"strings"
	"time"
)

const (
	sVer       = "0.0.7"
	sAddrDef   = "localhost"
	sKip       = "skip"
	sTokAnon   = "anonymous"
	sPolMaster = "global-management"
)

// In-memory JSON configuration representation
// Generated by https://github.com/bashtian/jsonutils , refactored
type PolicyS struct {
	Descr string   `json:"Descr,omitempty"`
	Name  string   `json:"Name"`
	Rules string   `json:"Rules"`
	Dc    []string `json:"Dc,omitempty"`
}
type RoleS struct {
	Descr    string   `json:"Descr,omitempty"`
	Name     string   `json:"Name"`
	Policies []string `json:"Policies,omitempty"`
}
type TokenS struct {
	Descr      string   `json:"Descr,omitempty"`
	Policies   []string `json:"Policies,omitempty"`
	Roles      []string `json:"Roles,omitempty"`
	AccessorID string   `json:"AccessorID"`
	Local      bool     `json:"Local,omitempty"`
}
type ConsulAcl struct {
	Policy []PolicyS
	Role   []RoleS `json:"Role,omitempty"`
	Token  []TokenS
}

var (
	sFileAcl = flag.String("f", "", "JSON file name with Consul ACL set")
	sAddr    = flag.String("a", sAddrDef, "Consul server address")
	sToken   = flag.String("t", "", "ACL agent token")
	iDebug   = flag.Bool("v", false, "Tune on verbose output")
	iDump    = flag.Bool("d", false, "Dump ACL")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Maintains Consul's ACL in required state, described in JSON file specified by -f switch.
Consul ACL can be saved (dumped) to terminal beforehand using -d switch.
Version %s
`, sVer)
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [-f <file> | -d] [-a address] [-t token] [-d]\n", os.Args[0])
		flag.PrintDefaults()
		// fmt.Fprintf(flag.CommandLine.Output(), "\n"+sHelp)
	}
	flag.Parse()
	if *sFileAcl == "" && *iDump == false {
		fmt.Printf("You must specify one of mandatory switch: '-f' or '-d'\n")
		flag.Usage()
		return
	}

	// Connect to Consul
	acl, config := ConsulConnect(sToken, sAddr)
	if acl == nil {
		log.Fatalf("ConsulConnect returned empty ACL\n")
	}

	// Read whole ACL into acL variable
	var acL AclList
	if err := acL.GetList(acl, config.Token); err != nil {
		log.Fatalf("GetList: %v\n", err)
	}

	// Dump ACL as JSON if iDump was specified
	if *iDump {
		if sJson, err := acL.Dump(); err == nil {
			fmt.Printf(sJson)
		} else {
			log.Fatalf("Dump: %v\n", err)
		}
		return
	}

	// Read ACL JSON list
	data, err := ioutil.ReadFile(*sFileAcl)
	if err != nil {
		log.Fatalf("ReadFile: %v: %q\n", err, *sFileAcl)
	}
	if !json.Valid(data) {
		log.Fatal(*sFileAcl + ": invalid JSON format\n")
	}

	var aclList ConsulAcl
	err = json.Unmarshal([]byte(data), &aclList)
	if err != nil {
		log.Fatal(err)
	}
	Log("aclList %+v\n\n", aclList)

	// Creating policy hash from parsed JSON
	aclPol := map[string]PolicyS{}
	for _, v := range aclList.Policy {
		Log("--- %+v\n", v)
		aclPol[v.Name] = v
	}
	Log("== aclPol %+v\n\n", aclPol)

	// Creating role hash from parsed JSON
	aclRole := map[string]RoleS{}
	for _, v := range aclList.Role {
		Log("--- %+v\n", v)
		aclRole[v.Name] = v
	}
	Log("== aclRole %+v\n\n", aclRole)

	// Creating token hash from parsed JSON
	aclToken := map[string]TokenS{}
	for _, v := range aclList.Token {
		Log("--- %+v\n", v)
		aclToken[v.AccessorID] = v
	}
	Log("== aclToken %+v\n\n", aclToken)

	// ===========================================================
	// Policy
	// ===========================================================
	aclPol1 := map[string]string{}
	for _, pol := range acL.poList {
		Log("== policy=%+v err=%v\n\n", pol, err)

		// Skipping marked policy
		if aclPol[pol.Name].Descr == sKip || pol.Name == sPolMaster {
			Log("Skipping policy %q\n", pol.Name)
			continue
		}

		// Removing unknown policy
		if aclPol[pol.Name].Name == "" {
			if _, err := acl.PolicyDelete(pol.ID, nil); err != nil {
				log.Fatalf("PolicyDelete: %v: %q\n", err, pol)
			} else {
				fmt.Printf("Removed policy %q\n", pol.Name)
			}
			continue
		}

		aclPol1[pol.Name] = pol.ID
		change := ""

		Log("=== dc %q %q %v\n", pol.Datacenters, aclPol[pol.Name].Dc, StrArrCmp(pol.Datacenters, aclPol[pol.Name].Dc))
		// Checking policy's datacenter
		if StrArrCmp(pol.Datacenters, aclPol[pol.Name].Dc) == false {
			change = "Datacenters: '" + strings.Join(pol.Datacenters, ",") + "' => '" + strings.Join(aclPol[pol.Name].Dc, ",") + "', "
			pol.Datacenters = aclPol[pol.Name].Dc
		}
		// Checking policy's description
		if pol.Description != aclPol[pol.Name].Descr {
			change += "Description: '" + pol.Description + "' => '" + aclPol[pol.Name].Descr + "', "
			pol.Description = aclPol[pol.Name].Descr
		}
		if pol.Rules != aclPol[pol.Name].Rules {
			change += "Rules: '" + pol.Rules + "' => '" + aclPol[pol.Name].Rules + "'"
			pol.Rules = aclPol[pol.Name].Rules
		}

		// Updating policy
		if change != "" {
			change = strings.TrimRight(change, ", ")
			_, _, err := acl.PolicyUpdate(pol, nil)
			if err != nil {
				log.Fatal(err)
				log.Fatalf("PolicyUpdate: %v: %q\n", err, pol)
			} else {
				fmt.Printf("Updated policy %q: %s\n", pol.Name, change)
			}
		}
		delete(aclPol, pol.Name)
	}

	// Creating absent policies
	for k, v := range aclPol {
		if aclPol[k].Descr == sKip {
			Log("Skipping policy %q\n", k)
			continue
		}
		_, _, err := acl.PolicyCreate(&api.ACLPolicy{Name: k, Rules: v.Rules, Description: v.Descr, Datacenters: v.Dc}, nil)
		if err != nil {
			log.Fatalf("PolicyCreate: %v: %q\n", err, v)
		} else {
			fmt.Printf("Created policy %q\n", k)
		}
	}
	Log("\n")

	// ===========================================================
	// Role
	// ===========================================================
	aclRole1 := map[string]string{}
	for _, role := range acL.roList {
		Log("== role=%+v err=%v\n\n", role, err)

		// Skipping marked role
		if aclRole[role.Name].Descr == sKip {
			Log("Skipping role %q\n", role.Name)
			continue
		}

		// Removing unknown role
		if aclRole[role.Name].Name == "" {
			if _, err := acl.RoleDelete(role.ID, nil); err != nil {
				log.Fatalf("RoleDelete: %v: %v\n", err, role)
			} else {
				fmt.Printf("Removed role %q\n", role.Name)
			}
			continue
		}

		aclRole1[role.Name] = role.ID

		change := ""
		// Checking role's description
		if role.Description != aclRole[role.Name].Descr {
			change += "Description: '" + role.Description + "' => '" + aclRole[role.Name].Descr + "', "
			role.Description = aclRole[role.Name].Descr
		}
		// Creating policy list to comapre
		pl := []string{}
		for _, p := range role.Policies {
			pl = append(pl, p.Name)
		}
		if StrArrCmp(pl, aclRole[role.Name].Policies) == false || role.Description != aclRole[role.Name].Descr {
			change += "Policies: '" + strings.Join(pl, ",") + "' => '" + strings.Join(aclRole[role.Name].Policies, ",") + "'"
			role.Policies = CreatePolicyRoleList(aclPol1, aclRole[role.Name].Policies)
		}
		// Updating role
		if change != "" {
			change = strings.TrimRight(change, ", ")
			_, _, err := acl.RoleUpdate(role, nil)
			if err != nil {
				log.Fatal(err)
				log.Fatalf("RoleUpdate: %v: %v\n", err, role)
			} else {
				fmt.Printf("Updated role %q: %s\n", role.Name, change)
			}
		}
		delete(aclRole, role.Name)
	}

	// Creating absent roles
	for k, v := range aclRole {
		if aclRole[k].Descr == sKip {
			Log("Skipping role %q\n", k)
			continue
		}
		poList := CreatePolicyRoleList(aclPol1, v.Policies)

		if _, _, err := acl.RoleCreate(&api.ACLRole{Name: k, Policies: poList, Description: v.Descr}, nil); err != nil {
			log.Fatal(err)
			log.Fatalf("RoleCreate: %v: %q\n", err, v)
		} else {
			fmt.Printf("Created role %q\n", k)
		}
	}
	Log("\n")

	// ===========================================================
	// Token
	// ===========================================================
	aclToken1 := map[string]string{}
	for _, token := range acL.toList {
		token, _, err := acl.TokenRead(token.AccessorID, nil)
		Log("\n== token=%+v err=%v\n\n", token, err)

		// Skipping marked token
		if aclToken[token.AccessorID].AccessorID == sKip || token.SecretID == config.Token || token.SecretID == sTokAnon {
			Log("Skipping token %q\n", token.Description)
			delete(aclToken, token.AccessorID)
			continue
		}

		// Removing unknown and legacy tokens
		if aclToken[token.AccessorID].AccessorID == "" || len(token.Rules) > 0 {
			if _, err := acl.TokenDelete(token.AccessorID, nil); err != nil {
				log.Fatalf("TokenDelete: %v: %v\n", err, token)
			} else {
				fmt.Printf("Removed token %q\n", token.AccessorID)
			}
			continue
		}

		aclToken1[token.AccessorID] = token.AccessorID

		change := ""
		// Checking token's description
		if token.Description != aclToken[token.AccessorID].Descr {
			change = "Description: '" + token.Description + "' => '" + aclToken[token.AccessorID].Descr + "', "
			token.Description = aclToken[token.AccessorID].Descr

		}
		// Creating policy list to comapre
		pl := []string{}
		for _, p := range token.Policies {
			pl = append(pl, p.Name)
		}
		Log("=== pl %q %q\n\n", pl, aclToken[token.AccessorID].Policies)
		// Updating token's policy list
		if StrArrCmp(pl, aclToken[token.AccessorID].Policies) == false {
			change += "Policies: '" + strings.Join(pl, ",") + "' => '" + strings.Join(aclToken[token.AccessorID].Policies, ",") + "', "
			token.Policies = CreatePolicyRoleList(aclPol1, aclToken[token.AccessorID].Policies)
		}

		// Creating roles list to comapre
		rl := []string{}
		for _, p := range token.Roles {
			rl = append(rl, p.Name)
		}
		Log("=== rl %q %q %v\n", rl, aclToken[token.AccessorID].Roles, StrArrCmp(rl, aclToken[token.AccessorID].Roles))
		// Updating token's roles list
		if StrArrCmp(rl, aclToken[token.AccessorID].Roles) == false {
			change += "Roles: '" + strings.Join(rl, ",") + "' => '" + strings.Join(aclToken[token.AccessorID].Roles, ",") + "'"
			token.Roles = CreatePolicyRoleList(aclRole1, aclToken[token.AccessorID].Roles)
		}

		// Updating token
		if change != "" {
			change = strings.TrimRight(change, ", ")
			if _, _, err := acl.TokenUpdate(token, nil); err != nil {
				log.Fatalf("TokenUpdate: %v: %v\n", err, token)
			} else {
				fmt.Printf("Updated token %q (%q): %q\n", token.Description, token.AccessorID, change)
			}
		}
		delete(aclToken, token.AccessorID)
	}

	// Creating absent tokens
	for _, v := range aclToken {
		if v.AccessorID == sKip {
			continue
		}

		poList := CreatePolicyRoleList(aclPol1, v.Policies)
		roList := CreatePolicyRoleList(aclRole1, v.Roles)
		if _, _, err := acl.TokenCreate(&api.ACLToken{AccessorID: v.AccessorID, Description: v.Descr,
			Policies: poList, Roles: roList, Local: v.Local}, nil); err != nil {
			log.Fatalf("TokenCreate: %v: %v\n", err, v)
		} else {
			fmt.Printf("Created token %q\n", v)
		}
	}
	// Token end

} // main

// ==================================================
// Functions and structures
// ==================================================

type AclList struct {
	poList []*api.ACLPolicy
	roList []*api.ACLRole
	toList []*api.ACLToken
	// poListLe []*api.ACLPolicyListEntry
}

func (al *AclList) GetList(acl *api.ACL, sTokMaster string) error {
	aclPoList, _, err := acl.PolicyList(nil)
	if err != nil {
		return err
	}
	for _, pol := range aclPoList {
		policy, _, err := acl.PolicyRead(pol.ID, nil)
		if err != nil {
			return err
		}
		if policy.Name == sPolMaster {
			continue
		}
		al.poList = append(al.poList, policy)
	}

	aclRoList, _, err := acl.RoleList(nil)
	if err != nil {
		return err
	}
	for _, role := range aclRoList {
		role, _, err := acl.RoleRead(role.ID, nil)
		if err != nil {
			return err
		}
		al.roList = append(al.roList, role)
	}

	aclToList, _, err := acl.TokenList(nil)
	if err != nil {
		return err
	}
	for _, token := range aclToList {
		token, _, err := acl.TokenRead(token.AccessorID, nil)
		if err != nil {
			return err
		}
		if token.SecretID == sTokMaster || token.SecretID == sTokAnon {
			continue
		}
		al.toList = append(al.toList, token)
	}

	return nil
}
func (al *AclList) Dump() (string, error) {
	var po []PolicyS
	var ro []RoleS
	var to []TokenS
	for _, pol := range al.poList {
		v := PolicyS{}
		v.Name = pol.Name
		v.Descr = pol.Description
		v.Rules = pol.Rules
		v.Dc = pol.Datacenters
		po = append(po, v)
	}
	for _, role := range al.roList {
		v := RoleS{}
		v.Name = role.Name
		v.Descr = role.Description
		v.Policies = RoleTokenToStrA(role.Policies)
		ro = append(ro, v)
	}
	for _, tok := range al.toList {
		v := TokenS{}
		v.Descr = tok.Description
		v.AccessorID = tok.AccessorID
		v.Policies = RoleTokenToStrA(tok.Policies)
		v.Roles = RoleTokenToStrA(tok.Roles)
		v.Local = tok.Local
		to = append(to, v)
	}
	acl := ConsulAcl{Policy: po, Role: ro, Token: to}
	Log("acl %+v\n\n", acl)
	bJson, err := json.Marshal(acl)
	if err != nil {
		return "", err
	}
	return string(bJson), nil
}

func CreatePolicyRoleList(prList map[string]string, list []string) []*api.ACLLink {
	pr := []*api.ACLLink{}
	for _, p := range list {
		pr = append(pr, &api.ACLLink{ID: prList[p], Name: p})
	}
	return pr
}

func Log(format string, a ...interface{}) {
	if *iDebug == true {
		fmt.Printf(format, a...)
	}
}

func StrArrCmp(a1, a2 []string) bool {
	rc := true
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
	return rc
}

func RoleTokenToStrA(al []*api.ACLLink) (sl []string) {
	for _, n := range al {
		sl = append(sl, n.Name)
	}
	return
}

func ConsulConnect(sToken, sAddr *string) (*api.ACL, *api.Config) {
	config := api.DefaultConfig()
	time30s, _ := time.ParseDuration("30s")
	config.WaitTime = time30s
	if *sToken != "" {
		config.Token = *sToken
	}
	Log("config.Token %v\n", config.Token)

	if *sAddr != sAddrDef {
		config.Address = *sAddr + ":8500"
	}
	client, err := api.NewClient(config)
	if err != nil {
		log.Fatalf("NewClient: %v\n", err)
		return nil, nil
	}
	return client.ACL(), config

}
