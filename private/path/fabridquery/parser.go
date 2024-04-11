package fabridquery

import (
	"fmt"
	"github.com/antlr/antlr4/runtime/Go/antlr"
	"github.com/scionproto/scion/antlr/pathpolicyconstraints"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/private/serrors"
	"strconv"
)

type errorListener struct {
	*antlr.DefaultErrorListener
	msg string
}

func (l *errorListener) SyntaxError(recognizer antlr.Recognizer, offendingSymbol interface{}, line,
	column int, msg string, e antlr.RecognitionException) {

	l.msg += fmt.Sprintf("%d:%d %s\n", line, column, msg)
}

type pathpolicyConstraintsListener struct {
	*pathpolicyconstraints.BasePathPolicyConstraintsListener
	stack []interface{}
}

func (l *pathpolicyConstraintsListener) push(s interface{}) {
	l.stack = append(l.stack, s)
}

func (l *pathpolicyConstraintsListener) pop() interface{} {
	var result interface{}
	if len(l.stack) == 0 {
		result = "X"
	} else {
		result = l.stack[len(l.stack)-1]
		l.stack = l.stack[:len(l.stack)-1]
	}
	return result
}

func (l *pathpolicyConstraintsListener) ExitIf(c *pathpolicyconstraints.IfContext) {
	t, ok := l.pop().(Expressions)
	if !ok {
		return
	}
	q, ok := l.pop().(Expressions)
	if !ok {
		return
	}
	l.push(Query{q, t, Nop{}})

}

func (l *pathpolicyConstraintsListener) ExitIfElse(c *pathpolicyconstraints.IfElseContext) {
	f, ok := l.pop().(Expressions)
	if !ok {
		return
	}
	t, ok := l.pop().(Expressions)
	if !ok {
		return
	}
	q, ok := l.pop().(Expressions)
	if !ok {
		return
	}
	l.push(Query{q, t, f})

}

func (l *pathpolicyConstraintsListener) ExitExpressionQuery(c *pathpolicyconstraints.ExpressionQueryContext) {
	id, ok := l.pop().(Query)
	if !ok {
		return
	}
	l.push(Expression{id})
}

func (l *pathpolicyConstraintsListener) ExitExpressionIdentifier(c *pathpolicyconstraints.ExpressionIdentifierContext) {
	id, ok := l.pop().(Identifier)
	if !ok {
		return
	}
	l.push(Expression{id})
}

// TODO(jvanbommel): --fabridquery "{0-0#0,0@G1101 ? (0-0#0,0@G1111  : 0-0#0,0@G1101} + 0-0#0,0@0"
func (l *pathpolicyConstraintsListener) ExitExpressionConcat(c *pathpolicyconstraints.ExpressionConcatContext) {
	right := l.pop().(Expressions)
	left := l.pop().(Expressions)
	l.push(ConcatExpression{left, right})
}

func (l *pathpolicyConstraintsListener) ExitParens(c *pathpolicyconstraints.ParensContext) {
	//l.push(Expression{l.pop().(Expressions)}) //TODO(jvanbommel) this is unneccessary, only keep for debugging
}

// ExitIdentifier is called when exiting the identifier production.
func (l *pathpolicyConstraintsListener) ExitIdentifier(c *pathpolicyconstraints.IdentifierContext) {
	policy, ok := l.pop().(Policy)
	if !ok {
		return
	}
	egIface, ok := l.pop().(Interface)
	if !ok {
		return
	}
	igIface, ok := l.pop().(Interface)
	if !ok {
		return
	}
	as, ok := l.pop().(AS)
	if !ok {
		return
	}
	isd, ok := l.pop().(ISD)
	if !ok {
		return
	}
	l.push(Identifier{
		Isd:    isd,
		As:     as,
		IgIntf: igIface,
		EgIntf: egIface,
		Policy: policy,
	})
}

// ExitWildcardISD is called when exiting the WildcardISD production.
func (l *pathpolicyConstraintsListener) ExitWildcardISD(c *pathpolicyconstraints.WildcardISDContext) {
	l.push(ISD{Wildcard: true})

}

// ExitISD is called when exiting the ISD production.
func (l *pathpolicyConstraintsListener) ExitISD(c *pathpolicyconstraints.ISDContext) {
	n, err := strconv.Atoi(c.GetText())
	if err != nil {
		l.push(ISD{Wildcard: true})
		return
	}
	l.push(ISD{Wildcard: false, Number: n})
}

// ExitWildcardAS is called when exiting the WildcardAS production.
func (l *pathpolicyConstraintsListener) ExitWildcardAS(c *pathpolicyconstraints.WildcardASContext) {
	l.push(AS{Wildcard: true})

}

// ExitLegacyAS is called when exiting the LegacyAS production.
func (l *pathpolicyConstraintsListener) ExitLegacyAS(c *pathpolicyconstraints.LegacyASContext) {
	as, err := addr.ParseASSep(c.GetText()[1:], "_")
	if err != nil {
		c.SetException(antlr.NewFailedPredicateException(c.GetParser(), c.GetText(), err.Error()))
	}
	l.push(AS{ASN: as})

}

// ExitAS is called when exiting the AS production.
func (l *pathpolicyConstraintsListener) ExitAS(c *pathpolicyconstraints.ASContext) {
	as, err := addr.ParseASSep(c.GetText()[1:], "_")
	if err != nil {
		c.SetException(antlr.NewFailedPredicateException(c.GetParser(), c.GetText(), err.Error()))
	}
	l.push(AS{ASN: as})
}

// ExitWildcardIFace is called when exiting the WildcardIFace production.
func (l *pathpolicyConstraintsListener) ExitWildcardIFace(c *pathpolicyconstraints.WildcardIFaceContext) {
	l.push(Interface{Wildcard: true})
}

// ExitIFace is called when exiting the IFace production.
func (l *pathpolicyConstraintsListener) ExitIFace(c *pathpolicyconstraints.IFaceContext) {
	n, err := strconv.Atoi(c.GetText())
	if err != nil {
		l.push(Interface{Wildcard: true})
		return
	}
	l.push(Interface{Wildcard: false, Number: n})
}

// ExitGlobalPolicy is called when exiting the GlobalPolicy production.
func (l *pathpolicyConstraintsListener) ExitGlobalPolicy(c *pathpolicyconstraints.GlobalPolicyContext) {
	n, err := strconv.Atoi(c.GetText()[1:])
	if err != nil {
		l.push(Policy{Type: WILDCARD_POLICY_TYPE})
		return
	}
	l.push(Policy{
		Type: STANDARD_POLICY_TYPE,
		Policy: &fabrid.Policy{
			Type:       fabrid.GlobalPolicy,
			Identifier: uint32(n),
		},
	})
}

// ExitLocalPolicy is called when exiting the LocalPolicy production.
func (l *pathpolicyConstraintsListener) ExitLocalPolicy(c *pathpolicyconstraints.LocalPolicyContext) {
	n, err := strconv.Atoi(c.GetText()[1:])
	if err != nil {
		l.push(Policy{Type: WILDCARD_POLICY_TYPE})
		return
	}
	l.push(Policy{
		Type: STANDARD_POLICY_TYPE,
		Policy: &fabrid.Policy{
			Type:       fabrid.LocalPolicy,
			Identifier: uint32(n),
		},
	})
}

// ExitWildcardPolicy is called when exiting the WildcardPolicy production.
func (l *pathpolicyConstraintsListener) ExitWildcardPolicy(c *pathpolicyconstraints.WildcardPolicyContext) {

	l.push(Policy{Type: WILDCARD_POLICY_TYPE})
}

// ExitWildcardPolicy is called when exiting the WildcardPolicy production.
func (l *pathpolicyConstraintsListener) ExitReject(c *pathpolicyconstraints.RejectContext) {

	l.push(Policy{Type: REJECT_POLICY_TYPE})
}

// ExitPolicyIndex is called when exiting the PolicyIndex production.
func (l *pathpolicyConstraintsListener) ExitPolicyIndex(c *pathpolicyconstraints.PolicyIndexContext) {
	// UNUSED
}

func ParseFabridQuery(input string) (Expressions, error) {
	istream := antlr.NewInputStream(input)
	lexer := pathpolicyconstraints.NewPathPolicyConstraintsLexer(istream)
	lexer.RemoveErrorListeners()
	errListener := &errorListener{}
	lexer.AddErrorListener(errListener)
	tstream := antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel)
	parser := pathpolicyconstraints.NewPathPolicyConstraintsParser(tstream)
	parser.RemoveErrorListeners()
	parser.AddErrorListener(errListener)
	listener := pathpolicyConstraintsListener{}
	antlr.ParseTreeWalkerDefault.Walk(&listener, parser.Start())
	if errListener.msg != "" || (len(listener.stack) != 1) {
		return nil, serrors.New(errListener.msg)
	}
	expr, ok := listener.stack[0].(Expressions)
	if !ok {
		return nil, serrors.New("Not a valid query")
	}
	return expr, nil
}