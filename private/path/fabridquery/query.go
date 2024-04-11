package fabridquery

import (
	"fmt"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/snet"
)

type TypedNumber struct {
	Wildcard bool
	Number   int
}

type ISD TypedNumber

func (i ISD) Matches(ia addr.ISD) bool {
	return i.Wildcard || ia == addr.ISD(i.Number)
}

func (i ISD) String() string {
	if i.Wildcard {
		return "*"
	}
	return fmt.Sprintf("%d", i.Number)

}

type AS struct {
	Wildcard bool
	ASN      addr.AS
}

func (a AS) Matches(iaas addr.AS) bool {
	return a.Wildcard || iaas == a.ASN
}

func (a AS) String() string {
	if a.Wildcard {
		return "*"
	}
	return fmt.Sprintf("%s", a.ASN)
}

type Interface TypedNumber

func (i Interface) Matches(intf common.IFIDType) bool {
	return i.Wildcard || intf == common.IFIDType(i.Number)
}

func (i Interface) String() string {
	if i.Wildcard {
		return "*"
	}
	return fmt.Sprintf("%d", i.Number)
}

const (
	WILDCARD_POLICY_TYPE = iota
	REJECT_POLICY_TYPE
	STANDARD_POLICY_TYPE
)

type Policy struct {
	Type uint8
	*fabrid.Policy
}

func (p Policy) String() string {
	if p.Type == WILDCARD_POLICY_TYPE {
		return "*"
	} else if p.Type == REJECT_POLICY_TYPE {
		return "reject"
	} else if p.Type == STANDARD_POLICY_TYPE {
		return fmt.Sprintf("%s", p.Policy.String())
	}
	return "unknown"
}

type Identifier struct {
	Isd    ISD
	As     AS
	IgIntf Interface
	EgIntf Interface
	Policy Policy
}

func (i Identifier) String() string {
	return fmt.Sprintf("{ Isd %s, As %s, IgIntf %s, EgIntf %s, Policy %s }", i.Isd, i.As, i.IgIntf,
		i.EgIntf, i.Policy)
}

type Expressions interface {
	Evaluate([]snet.HopInterface, *MatchList) (bool, *MatchList)
	String() string
}

type Expression struct {
	Expressions
}

type Query struct {
	Q Expressions
	T Expressions
	F Expressions
}

func (q Query) String() string {
	return fmt.Sprintf(" Query { Query %s, True %s, False %s } ", q.Q, q.T, q.F)
}

type Nop struct{}

func (n Nop) String() string {
	return "Nop"
}

type ConcatExpression struct {
	Left  Expressions
	Right Expressions
}

func (c ConcatExpression) String() string {
	return fmt.Sprintf(" Concat { Left %s, Right %s } ", c.Left, c.Right)
}
