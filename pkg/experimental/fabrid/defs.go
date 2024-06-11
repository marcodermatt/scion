// Copyright 2023 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
