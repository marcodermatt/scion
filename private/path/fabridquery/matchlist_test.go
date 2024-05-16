package fabridquery_test

//TODO(jvanbommel)
//
//import (
//	"github.com/scionproto/scion/pkg/experimental/fabrid"
//	"github.com/scionproto/scion/private/path/fabridquery"
//	"testing"
//)
//
//func TestMatchList_Copy(t *testing.T) {
//	tcs := []struct {
//		desc string
//		ml   *fabridquery.MatchList
//	}{
//		{"Empty list",
//			&fabridquery.MatchList{[]*fabridquery.Policy{}},
//		},
//		{"One policy",
//			&fabridquery.MatchList{[]*fabridquery.Policy{&fabridquery.Policy{Type: fabridquery.STANDARD_POLICY_TYPE, Policy: &fabrid.Policy{Index: 1}}}},
//		},
//		{"Mix policy types",
//			&fabridquery.MatchList{[]*fabridquery.Policy{&fabridquery.Policy{Type: fabridquery.STANDARD_POLICY_TYPE, Policy: &fabrid.Policy{Index: 1}}, &fabridquery.Policy{Type: fabridquery.REJECT_POLICY_TYPE}}},
//		},
//	}
//
//	for _, tc := range tcs {
//		t.Run(tc.desc, func(t *testing.T) {
//			result := tc.ml.Copy()
//			if len(result.SelectedPolicies) != len(tc.ml.SelectedPolicies) {
//				t.Errorf("Expected %d, got %d", len(tc.ml.SelectedPolicies), len(result.SelectedPolicies))
//			}
//			for i, p := range result.SelectedPolicies {
//				if p != tc.ml.SelectedPolicies[i] {
//					t.Errorf("Expected %v, got %v", p, tc.ml.SelectedPolicies[i])
//				}
//			}
//		})
//	}
//}
//
//func TestMatchList_StorePolicy(t *testing.T) {
//	tcs := []struct {
//		name    string
//		ml      *MatchList
//		hop     int
//		policy  *Policy
//		wantMl  *MatchList
//	}{
//		{"Empty list, first hop",
//			&MatchList{[]*Policy{}}, 0, &Policy{},
//			&MatchList{[]*Policy{&Policy{}}},
//		},
//		{"Empty list, second hop",
//			&MatchList{[]*Policy{}}, 1, &Policy{},
//			&MatchList{[]*Policy{nil, &Policy{}}},
//		},
//		{"Existing policy",
//			&MatchList{[]*Policy{&Policy{}}},
//			0, &Policy{Type: PROGRAMMED_POLICY_TYPE},
//			&MatchList{[]*Policy{&Policy{}}},
//		},
//	}
//	for _, tc := range tcs {
//		t.Run(tc.name, func(t *testing.T) {
//			tc.ml.StorePolicy(tc.hop, tc.policy)
//			if tc.ml != tc.wantMl {
//				t.Errorf("Expected %v, got %v", tc.wantMl, tc.ml)
//			}
//		})
//	}
//}
//
//func TestMatchList_Accepted(t *testing.T) {
//	tcs := []struct {
//		name   string
//		ml     *MatchList
//		wantAc bool
//	}{
//		{"Empty list",
//			&MatchList{[]*Policy{}}, true},
//		{"All nil",
//			&MatchList{[]*Policy{nil, nil}}, false},
//		{"All reject",
//			&MatchList{[]*Policy{&Policy{Type: REJECT_POLICY_TYPE}, &Policy{Type: REJECT_POLICY_TYPE}}}, false},
//		{"All accept",
//			&MatchList{[]*Policy{&Policy{Type: PROGRAMMED_POLICY_TYPE}, &Policy{Type: PROGRAMMED_POLICY_TYPE}}}, true},
//		{"Mixed accept/reject",
//			&MatchList{[]*Policy{&Policy{Type: PROGRAMMED_POLICY_TYPE}, &Policy{Type: REJECT_POLICY_TYPE}}}, false},
//	}
//
//	for _, tc := range tcs {
//		t.Run(tc.name, func(t *testing.T) {
//			got := tc.ml.Accepted()
//			if got != tc.wantAc {
//				t.Errorf("Expected %v, got %v", tc.wantAc, got)
//			}
//		})
//	}
//}
//
//func TestMatchList_Policies(t *testing.T) {
//	tcs := []struct {
//		name  string
//		ml    *MatchList
//		wantP []fabrid.PolicyID
//	}{
//		{"Empty list",
//			&MatchList{[]*Policy{}}, []fabrid.PolicyID{}},
//		{"All nil",
//			&MatchList{[]*Policy{nil, nil}}, []fabrid.PolicyID{0, 0}},
//		{"One valid policy",
//			&MatchList{[]*Policy{&Policy{Type: PROGRAMMED_POLICY_TYPE, Policy: &fabrid.Policy{Index: 1}}}}, []fabrid.PolicyID{1}},
//		{"One invalid policy",
//			&MatchList{[]*Policy{&Policy{Type: REJECT_POLICY_TYPE, Policy: &fabrid.Policy{Index: 1}}}}, []fabrid.PolicyID{0}},
//		{"Mixed invalid and valid policies",
//			&MatchList{[]*Policy{&Policy{Type: PROGRAMMED_POLICY_TYPE, Policy: &fabrid.Policy{Index: 1}}, &Policy{Type: REJECT_POLICY_TYPE}}}, []fabrid.PolicyID{1, 0}},
//	}
//
//	for _, tc := range tcs {
//		t.Run(tc.name, func(t *testing.T) {
//			got := tc.ml.Policies()
//			for i, p := range got {
//				if p != tc.wantP[i] {
//					t.Errorf("Expected %v items, got %v", p, tc.wantP[i])
//				}
//			}
//		})
//	}
//}
