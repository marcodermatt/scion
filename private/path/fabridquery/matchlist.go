package fabridquery

import (
	"fmt"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/snet"
)

type MatchList struct {
	SelectedPolicies []*Policy
}

func (ml MatchList) Copy() *MatchList {
	duplicate := make([]*Policy, len(ml.SelectedPolicies))
	copy(duplicate, ml.SelectedPolicies)
	return &MatchList{duplicate}
}

// StorePolicy only stores a policy if there has not been one already set for the hop.
func (ml MatchList) StorePolicy(hop int, policy *Policy) {
	if ml.SelectedPolicies[hop] == nil {
		ml.SelectedPolicies[hop] = policy
	}
}

// Accepted checks if all hops have at least a policy assigned, which is not the rejection policy
func (ml MatchList) Accepted() bool {
	for _, policy := range ml.SelectedPolicies {
		if policy == nil || policy.Type == REJECT_POLICY_TYPE {
			return false
		}
	}
	return true
}

func (ml MatchList) Policies() (pols []*fabrid.PolicyID) {
	pols = make([]*fabrid.PolicyID, len(ml.SelectedPolicies))
	for i, selected := range ml.SelectedPolicies {
		if selected == nil {
			pols[i] = nil
			fmt.Println(i, " is not using a policy")
		} else if selected.Type == WILDCARD_POLICY_TYPE || selected.Type == REJECT_POLICY_TYPE {
			zeroPol := fabrid.PolicyID(0)
			pols[i] = &zeroPol
			fmt.Println(i, " is using zero policy")
		} else {
			pols[i] = &selected.Policy.Index
			fmt.Println(i, " is using policy ", selected.String(), " index: ", selected.Policy.Index)
		}
	}
	return pols
}

func (e Expression) Evaluate(pi []snet.HopInterface, ml *MatchList) (bool, *MatchList) {
	return e.Expressions.Evaluate(pi, ml)
}

func (e Query) Evaluate(pi []snet.HopInterface, ml *MatchList) (bool, *MatchList) {
	mlOriginal := ml.Copy()
	qRes, _ := e.Q.Evaluate(pi, mlOriginal)
	if qRes {
		return e.T.Evaluate(pi, ml)
	}
	return e.F.Evaluate(pi, ml)
}

func (e ConcatExpression) Evaluate(pi []snet.HopInterface, ml *MatchList) (bool, *MatchList) {
	left, mlLeft := e.Left.Evaluate(pi, ml)
	right, mlRight := e.Right.Evaluate(pi, mlLeft)
	return left && right, mlRight
}

func (e Identifier) Evaluate(pi []snet.HopInterface, ml *MatchList) (bool, *MatchList) {
	matched := false
	for i, p := range pi {
		// Check if ISD, AS and intferfaces match between the query and a hop in the path.
		if !(e.Isd.Matches(p.IA.ISD()) && e.As.Matches(p.IA.AS()) && e.IgIntf.Matches(p.IgIf) &&
			e.EgIntf.Matches(p.EgIf)) {
			continue
		}
		// If so and the query sets a wildcard or reject policy, assign this and continue evaluating
		// the query
		if e.Policy.Type == WILDCARD_POLICY_TYPE || e.Policy.Type == REJECT_POLICY_TYPE {
			if e.Policy.Type == WILDCARD_POLICY_TYPE && len(p.Policies) > 0 {
				ml.StorePolicy(i, &e.Policy)
			}
			matched = true
			continue
		}
		// Check if the query's policy matches a policy that is available for this hop.
		for _, pol := range p.Policies {
			if pol.Identifier == e.Policy.Identifier && e.Policy.Policy.Type == pol.Type {

				ml.StorePolicy(i, &Policy{
					Type:   STANDARD_POLICY_TYPE,
					Policy: pol,
				})
				matched = true
			}
		}

	}
	return matched, ml
}

func (n Nop) Evaluate(_ []snet.HopInterface, list *MatchList) (bool, *MatchList) {
	return true, list
}
