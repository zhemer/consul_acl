package main

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/consul/api"
	"log"
	"log/slog"
	"strings"
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
	Policies    map[string]Policy // Policy name is a key
	Roles       map[string]Role   `json:"Roles,omitempty"` // Role name is a key
	Tokens      map[string]Token  // SecretID is a key
	consulAcl   *api.ACL
	consulToken string
}

// Dump Consul ACL to string
// TODO: make pretty formatted json
func (acl *Acl) Dump() (string, error) {
	policies := map[string]Policy{}
	//for _, policy := range policyList {
	policyList, err := acl.GetPolicyList()
	if err != nil {
		return "", fmt.Errorf("GetPolicyList: %w", err)
	}
	for _, policy := range policyList {
		policies[policy.Name] = Policy{
			Description: policy.Description,
			Rules:       policy.Rules,
			Dc:          policy.Datacenters}
	}

	roles := map[string]Role{}
	roleList, err := acl.GetRoleList()
	if err != nil {
		return "", fmt.Errorf("GetRoleList: %w", err)
	}
	for _, role := range roleList {
		roles[role.Name] = Role{
			Description: role.Description,
			Policies:    ACLLinkToStringList(role.Policies)}
	}

	tokens := map[string]Token{}
	tokenList, err := acl.GetTokenList()
	if err != nil {
		return "", fmt.Errorf("GetRoleList: %w", err)
	}
	for _, token := range tokenList {
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

// Ensure Consul ACL policies list equils to the our.json list
func (acl Acl) SyncPolicies() (map[string]string, error) {
	policyNameToId := map[string]string{}

	policyList, err := acl.GetPolicyList()
	if err != nil {
		return nil, fmt.Errorf("GetPolicyList: %w", err)
	}

	for _, policy := range policyList {
		slog.Debug("policy=%v", policy)
		// Skipping policy marked as "skip" or masterPolicy
		if acl.Policies[policy.Name].Description == sKip || policy.Name == masterPolicy {
			slog.Debug("Skipping policy %q", policy.Name)
			continue
		}

		// Removing unknown policy
		if _, ok := acl.Policies[policy.Name]; !ok {
			if _, err := acl.consulAcl.PolicyDelete(policy.ID, nil); err != nil {
				return nil, fmt.Errorf("PolicyDelete for %v: %w", policy, err)
			}
			log.Printf("Removed policy %q", policy.Name)
			continue
		}

		policyNameToId[policy.Name] = policy.ID
		change := ""

		slog.Debug(fmt.Sprintf("policy Datacenters %q %q %v", policy.Datacenters,
			acl.Policies[policy.Name].Dc, StringsListsCompare(policy.Datacenters, acl.Policies[policy.Name].Dc)))
		// Checking policy datacenter
		if !StringsListsCompare(policy.Datacenters, acl.Policies[policy.Name].Dc) {
			change = "Datacenters: '" + strings.Join(policy.Datacenters, ",") + "' => '" +
				strings.Join(acl.Policies[policy.Name].Dc, ",") + "', "
			policy.Datacenters = acl.Policies[policy.Name].Dc
		}
		// Checking policy description
		if policy.Description != acl.Policies[policy.Name].Description {
			change += "Description: '" + policy.Description + "' => '" + acl.Policies[policy.Name].Description + "', "
			policy.Description = acl.Policies[policy.Name].Description
		}
		if policy.Rules != acl.Policies[policy.Name].Rules {
			change += "Rules: '" + policy.Rules + "' => '" + acl.Policies[policy.Name].Rules + "'"
			policy.Rules = acl.Policies[policy.Name].Rules
		}

		// Updating policy
		if change != "" {
			change = strings.TrimRight(change, ", ")
			_, _, err := acl.consulAcl.PolicyUpdate(policy, nil)
			if err != nil {
				return nil, fmt.Errorf("PolicyUpdate for %v: %w", policy, err)
			}
			log.Printf("Updated policy %q: %s", policy.Name, change)
		}
		delete(acl.Policies, policy.Name)
	}

	// Creating absent policies
	for k, v := range acl.Policies {
		if v.Description == sKip {
			slog.Debug("Skipping policy %q", k)
			continue
		}
		_, _, err := acl.consulAcl.PolicyCreate(&api.ACLPolicy{Name: k, Rules: v.Rules, Description: v.Description, Datacenters: v.Dc}, nil)
		if err != nil {
			return nil, fmt.Errorf("PolicyCreate for %v: %w", v, err)
		}
		log.Printf("Created policy %q", k)
	}
	return policyNameToId, nil
}

// Ensure Consul ACL roles list equils to the our.json list
func (acl Acl) SyncRoles(policyNameToId map[string]string) (map[string]string, error) {
	roleNameToId := map[string]string{}

	roleList, err := acl.GetRoleList()
	if err != nil {
		return nil, fmt.Errorf("GetRoleList: %w", err)
	}

	for _, role := range roleList {
		slog.Debug(fmt.Sprintf("role=%+v", role))

		// Skipping marked role
		if acl.Roles[role.Name].Description == sKip {
			slog.Debug(fmt.Sprintf("Skipping role %q", role.Name))
			continue
		}

		// Removing unknown role
		if _, ok := acl.Roles[role.Name]; !ok {
			if _, err := acl.consulAcl.RoleDelete(role.ID, nil); err != nil {
				return nil, fmt.Errorf("RoleDelete for %v: %w", role.Name, err)
			}
			log.Printf("Removed role %q", role.Name)
			continue
		}

		roleNameToId[role.Name] = role.ID

		change := ""
		// Checking role's description
		if role.Description != acl.Roles[role.Name].Description {
			change += "Description: '" + role.Description + "' => '" + acl.Roles[role.Name].Description + "', "
			role.Description = acl.Roles[role.Name].Description
		}
		// Creating roles policy list to compare
		var rpl []string
		for _, p := range role.Policies {
			rpl = append(rpl, p.Name)
		}
		if !StringsListsCompare(rpl, acl.Roles[role.Name].Policies) || role.Description != acl.Roles[role.Name].Description {
			change += "Policies: '" + strings.Join(rpl, ",") + "' => '" + strings.Join(acl.Roles[role.Name].Policies, ",") + "'"
			role.Policies = StringMapToACLLinkList(policyNameToId, acl.Roles[role.Name].Policies)
		}
		// Updating role
		if change != "" {
			change = strings.TrimRight(change, ", ")
			_, _, err := acl.consulAcl.RoleUpdate(role, nil)
			if err != nil {
				return nil, fmt.Errorf("RoleUpdatefor for %v: %q", role.Name, err)
			}
			log.Printf("Updated role %q: %s", role.Name, change)
		}
		delete(acl.Roles, role.Name)
	}

	// Creating absent roles
	for k, v := range acl.Roles {
		if v.Description == sKip {
			slog.Debug(fmt.Sprintf("Skipping role %q", k))
			continue
		}
		policyList := StringMapToACLLinkList(policyNameToId, v.Policies)

		if _, _, err := acl.consulAcl.RoleCreate(&api.ACLRole{Name: k, Policies: policyList, Description: v.Description}, nil); err != nil {
			return nil, fmt.Errorf("RoleCreate for %v: %q", k, err)
		}
		log.Printf("Created role %q", k)
	}
	return roleNameToId, nil
}

// Ensure Consul ACL tokens list equils to the our.json list
func (acl Acl) SyncTokens(policyNameToId map[string]string, roleNameToId map[string]string) error {

	tokenList, err := acl.GetTokenList()
	if err != nil {
		return fmt.Errorf("GetTokenList: %w", err)
	}

	for _, token := range tokenList {
		slog.Debug(fmt.Sprintf("token %+v", token))

		// Skipping marked token
		if acl.Tokens[token.SecretID].Description == sKip ||
			token.SecretID == acl.consulToken || token.SecretID == anonymousToken {
			slog.Debug(fmt.Sprintf("Skipping token %q (%v)", token.Description, token.SecretID))
			delete(acl.Tokens, token.SecretID)
			continue
		}

		// Removing unknown and legacy tokens(len(token.Rules)>0)
		legacy := ""
		if len(token.Rules) > 0 {
			legacy = " legacy"
		}
		if _, ok := acl.Tokens[token.SecretID]; !ok || legacy != "" {
			if _, err := acl.consulAcl.TokenDelete(token.AccessorID, nil); err != nil {
				return fmt.Errorf("TokenDelete%v for %+v: %w", legacy, token, err)
			}
			log.Printf("Removed%v token %q (%+v)", legacy, token.Description, token)
			continue
		}

		change := ""
		// Checking token description
		if token.Description != acl.Tokens[token.SecretID].Description {
			change = "Description: '" + token.Description + "' => '" + acl.Tokens[token.SecretID].Description + "', "
			token.Description = acl.Tokens[token.SecretID].Description

		}
		// Creating tokens policy list to compare
		var tokenPolicyList []string
		for _, p := range token.Policies {
			tokenPolicyList = append(tokenPolicyList, p.Name)
		}
		slog.Debug(fmt.Sprintf("Policies: server: %q file: %q StringsListsCompare: %v", tokenPolicyList,
			acl.Tokens[token.SecretID].Policies,
			StringsListsCompare(tokenPolicyList, acl.Tokens[token.SecretID].Policies)))
		// Updating token policy list
		if !StringsListsCompare(tokenPolicyList, acl.Tokens[token.SecretID].Policies) {
			change += "Policies: '" + strings.Join(tokenPolicyList, ",") + "' => '" +
				strings.Join(acl.Tokens[token.SecretID].Policies, ",") + "', "
			token.Policies = StringMapToACLLinkList(policyNameToId, acl.Tokens[token.SecretID].Policies)
		}

		// Creating token  roles list to compare
		var tokeRoleList []string
		for _, p := range token.Roles {
			tokeRoleList = append(tokeRoleList, p.Name)
		}
		slog.Debug(fmt.Sprintf("Roles: server: %q file: %q StringsListsCompare: %v", tokeRoleList,
			acl.Tokens[token.SecretID].Roles,
			StringsListsCompare(tokeRoleList, acl.Tokens[token.SecretID].Roles)))
		// Updating token's roles list
		if !StringsListsCompare(tokeRoleList, acl.Tokens[token.SecretID].Roles) {
			change += "Roles: '" + strings.Join(tokeRoleList, ",") + "' => '" + strings.Join(acl.Tokens[token.SecretID].Roles, ",") + "'"
			token.Roles = StringMapToACLLinkList(roleNameToId, acl.Tokens[token.SecretID].Roles)
		}

		// Updating token
		if change != "" {
			change = strings.TrimRight(change, ", ")
			if _, _, err := acl.consulAcl.TokenUpdate(token, nil); err != nil {
				return fmt.Errorf("TokenUpdate for %v: %w", token, err)
			}
			log.Printf("Updated token %q (%q): %q", token.Description, token.SecretID, change)
		}
		delete(acl.Tokens, token.SecretID)
	}

	// Creating absent tokens
	slog.Debug(fmt.Sprintf("aclTokens %+v", acl.Tokens))
	for k, v := range acl.Tokens {
		if k == sKip {
			continue
		}
		policyList := StringMapToACLLinkList(policyNameToId, v.Policies)
		roleList := StringMapToACLLinkList(roleNameToId, v.Roles)
		if _, _, err := acl.consulAcl.TokenCreate(&api.ACLToken{
			SecretID: k, Description: v.Description,
			Policies: policyList, Roles: roleList, Local: v.Local}, nil); err != nil {
			return fmt.Errorf("TokenCreate for %+v: %w", v, err)
		}
		log.Printf("Created token %+v", v)
	}
	return nil
}

// Get policies list from Consul
func (acl *Acl) GetPolicyList() ([]*api.ACLPolicy, error) {
	var policyList []*api.ACLPolicy
	aclPolicyList, _, err := acl.consulAcl.PolicyList(nil)
	if err != nil {
		return nil, fmt.Errorf("PolicyList: %w", err)
	}
	for _, pol := range aclPolicyList {
		policy, _, err := acl.consulAcl.PolicyRead(pol.ID, nil)
		if err != nil {
			return nil, fmt.Errorf("PolicyRead: %w", err)
		}
		if policy.Name == masterPolicy {
			continue
		}
		policyList = append(policyList, policy)
	}
	return policyList, nil
}

// Get roles list from Consul
func (acl *Acl) GetRoleList() ([]*api.ACLRole, error) {
	var roleList []*api.ACLRole
	aclRoleList, _, err := acl.consulAcl.RoleList(nil)
	if err != nil {
		return nil, fmt.Errorf("RoleList: %w", err)
	}
	for _, role := range aclRoleList {
		role, _, err := acl.consulAcl.RoleRead(role.ID, nil)
		if err != nil {
			return nil, fmt.Errorf("RoleRead: %w", err)
		}
		roleList = append(roleList, role)
	}
	return roleList, nil
}

// Get tokens list from Consul
func (acl *Acl) GetTokenList() ([]*api.ACLToken, error) {
	var tokenList []*api.ACLToken
	aclTokenList, _, err := acl.consulAcl.TokenList(nil)
	if err != nil {
		return nil, fmt.Errorf("TokenList: %w", err)
	}
	for _, token := range aclTokenList {
		token, _, err := acl.consulAcl.TokenRead(token.AccessorID, nil)
		if err != nil {
			return nil, fmt.Errorf("TokenRead: %w", err)
		}
		if token.SecretID == acl.consulToken || token.SecretID == anonymousToken {
			continue
		}
		tokenList = append(tokenList, token)
	}
	return tokenList, nil
}
