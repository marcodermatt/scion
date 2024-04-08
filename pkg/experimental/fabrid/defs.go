package fabrid

import "fmt"

type PolicyID uint8
type PolicyType int32

const (
	LocalPolicy  PolicyType = 0
	GlobalPolicy PolicyType = 1
)

type Policy struct {
	Type       PolicyType
	Identifier uint32
	Index      PolicyID
}

func (fpi *Policy) String() string {
	if fpi.Type == GlobalPolicy {
		return fmt.Sprintf("G%d", fpi.Identifier)
	} else if fpi.Type == LocalPolicy {
		return fmt.Sprintf("L%d", fpi.Identifier)
	}
	return ""
}
