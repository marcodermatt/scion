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

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"github.com/scionproto/scion/pkg/log"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	ext "github.com/scionproto/scion/pkg/slayers/extension"
)

type FabridPolicyID struct {
	ID uint8
}

const FabridMacInputSize int = 46

//	MAC input:
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| Identifier (8B)                                     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| Cons Ingress (2B)        |  Cons Egress (2B)        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |ePolicyID(1B)|sHostLen(1B)| SrcHostAddr (4-16 B)     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func computeFabridHVF(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, resultBuffer []byte,
	key []byte, ingress uint16, egress uint16) error {
	if len(key) != 16 {
		return serrors.New("Wrong key length", "expected", 16, "actual", len(key))
	}
	if len(tmpBuffer) < FabridMacInputSize {
		return serrors.New("tmpBuffer too small", "expected",
			FabridMacInputSize, "actual", len(tmpBuffer))
	}
	if len(resultBuffer) < 16 {
		return serrors.New("resultBuffer too small", "expected",
			16, "actual", len(resultBuffer))
	}

	id.Serialize(tmpBuffer[0:8])

	srcAddr := s.RawSrcAddr
	requiredLen := 14 + len(srcAddr)
	binary.BigEndian.PutUint16(tmpBuffer[8:10], ingress)
	binary.BigEndian.PutUint16(tmpBuffer[10:12], egress)
	tmpBuffer[12] = f.EncryptedPolicyID
	tmpBuffer[13] = byte(s.SrcAddrType.Length())
	copy(tmpBuffer[14:requiredLen], srcAddr)

	macBlock(key, tmpBuffer[30:46], tmpBuffer[:requiredLen], resultBuffer[:])
	return nil
}

func ComputeBaseHVF(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, key []byte, ingress uint16, egress uint16) error {
	computedHVF := make([]byte, 16)
	err := computeFabridHVF(f, id, s, tmpBuffer, computedHVF, key, ingress, egress)
	if err != nil {
		return err
	}
	computedHVF[0] &= 0x3f // ignore first two (left) bits
	copy(f.HopValidationField[:], computedHVF[0:3])
	return nil
}

func ComputeVerifiedHVF(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, key []byte, ingress uint16, egress uint16) error {
	computedHVF := make([]byte, 16)
	err := computeFabridHVF(f, id, s, tmpBuffer, computedHVF, key, ingress, egress)
	if err != nil {
		return err
	}
	computedHVF[3] &= 0x3f // ignore first two (left) bits
	copy(f.HopValidationField[:], computedHVF[3:6])
	return nil
}

func VerifyAndUpdate(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	s *slayers.SCION, tmpBuffer []byte, key []byte, ingress uint16, egress uint16) error {
	computedHVF := make([]byte, 16)
	err := computeFabridHVF(f, id, s, tmpBuffer, computedHVF, key, ingress, egress)
	if err != nil {
		return err
	}
	computedHVF[0] &= 0x3f // ignore first two (left) bits
	if !bytes.Equal(computedHVF[:3], f.HopValidationField[:]) {
		return serrors.New("HVF is not valid")
	}
	computedHVF[3] &= 0x3f // ignore first two (left) bits
	copy(f.HopValidationField[:], computedHVF[3:6])
	return nil
}

func ComputePolicyID(f *ext.FabridHopfieldMetadata, id *ext.IdentifierOption,
	key []byte) (FabridPolicyID, error) {

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return FabridPolicyID{}, err
	}
	buf := make([]byte, aes.BlockSize)
	if err = id.Serialize(buf); err != nil {
		return FabridPolicyID{}, err
	}
	cipher.Encrypt(buf, buf)
	policyID := f.EncryptedPolicyID ^ buf[0]
	fp := FabridPolicyID{
		ID: policyID,
	}
	return fp, nil
}

func EncryptPolicyID(f *FabridPolicyID, id *ext.IdentifierOption,
	key []byte) (uint8, error) {

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}
	buf := make([]byte, aes.BlockSize)
	if err = id.Serialize(buf); err != nil {
		return 0, err
	}
	cipher.Encrypt(buf, buf)
	policyID := f.ID ^ buf[0]
	return policyID, nil
}

// VerifyPathValidator recomputes the path validator from the updated HVFs and compares it
// with the path validator in the packet. Returns validation number and reply for path validation.
// `tmpBuffer` requires at least (numHops*3 rounded up to next multiple of 16) + 16 bytes
func VerifyPathValidator(f *ext.FabridOption, tmpBuffer []byte, pathKey []byte) (uint8, uint32, error) {
	inputLength := 3 * len(f.HopfieldMetadata)
	requiredBufferLength := 16 + (inputLength+15)&^15
	if len(tmpBuffer) < requiredBufferLength {
		return 0, 0, serrors.New("tmpBuffer length is invalid", "expected", requiredBufferLength, "actual", len(tmpBuffer))
	}
	for i, meta := range f.HopfieldMetadata {
		copy(tmpBuffer[16+i*3:16+(i+1)*3], meta.HopValidationField[:3])
	}
	err := macBlock(pathKey, tmpBuffer[:16], tmpBuffer[16:16+inputLength], tmpBuffer[16:])
	if err != nil {
		return 0, 0, err
	}
	validationNumber := tmpBuffer[20]
	validationReply := binary.BigEndian.Uint32(tmpBuffer[21:25])
	if !bytes.Equal(tmpBuffer[16:20], f.PathValidator[:]) {
		return validationNumber, validationReply, serrors.New("Path validator is not valid", "validator", base64.StdEncoding.EncodeToString(f.PathValidator[:]), "computed", base64.StdEncoding.EncodeToString(tmpBuffer[16:20]))
	}
	return validationNumber, validationReply, nil
}

// InitValidators sets all HVFs of the FABRID option and computes the
// path validator.
func InitValidators(f *ext.FabridOption, id *ext.IdentifierOption, s *slayers.SCION, tmpBuffer []byte, pathKey []byte,
	asHostKeys map[addr.IA]drkey.ASHostKey, asAsKeys map[addr.IA]drkey.Level1Key, ias []addr.IA, ingresses []uint16, egresses []uint16) (uint8, uint32, error) {

	outBuffer := make([]byte, 16)
	pathValInputLength := 3 * len(f.HopfieldMetadata)
	pathValBuffer := make([]byte, (pathValInputLength+15)&^15)
	for i, meta := range f.HopfieldMetadata {
		if meta.FabridEnabled {
			var key drkey.Key
			if meta.ASLevelKey {
				asAsKey, found := asAsKeys[ias[i]]
				if !found {
					return 0, 0, serrors.New("InitValidators expected AS to AS key but was not in dictionary", "AS", ias[i])
				}
				key = asAsKey.Key
			} else {
				asHostKey, found := asHostKeys[ias[i]]
				if !found {
					return 0, 0, serrors.New("InitValidators expected AS to AS key but was not in dictionary", "AS", ias[i])
				}
				key = asHostKey.Key
			}

			err := computeFabridHVF(meta, id, s, tmpBuffer, outBuffer, key[:], ingresses[i], egresses[i])
			if err != nil {
				return 0, 0, err
			}
			outBuffer[0] &= 0x3f // ignore first two (left) bits
			outBuffer[3] &= 0x3f // ignore first two (left) bits
			copy(meta.HopValidationField[:3], outBuffer[:3])
			copy(pathValBuffer[i*3:(i+1)*3], outBuffer[3:6])
		}
	}
	err := macBlock(pathKey, tmpBuffer[:16], pathValBuffer[:pathValInputLength], pathValBuffer)
	if err != nil {
		return 0, 0, err
	}
	copy(f.PathValidator[:4], pathValBuffer[:4])
	return pathValBuffer[4], binary.BigEndian.Uint32(pathValBuffer[5:9]), nil
}

func computeFabridControlValidator(fc *ext.FabridControlOption, resultBuffer []byte, pathKey []byte) error {
	dataLen := ext.FabridControlOptionDataLen(fc.Type)
	var fcMacInputLength int
	switch fc.Type {
	case ext.ValidationConfig, ext.StatisticsRequest:
		fcMacInputLength = 1 + 8 + dataLen
	case ext.ValidationConfigAck, ext.ValidationResponse, ext.StatisticsResponse:
		fcMacInputLength = 1 + dataLen

	}
	macInputBuf := make([]byte, (fcMacInputLength+15)&^15) // Next multiple of 16 for macBlock()$
	tmpBuf := make([]byte, 16)
	macInputBuf[0] = uint8(fc.Type)
	binary.BigEndian.PutUint32(macInputBuf[1:5], fc.Timestamp)
	binary.BigEndian.PutUint32(macInputBuf[5:9], fc.PacketID)
	copy(macInputBuf[9:fcMacInputLength], fc.Data)
	err := macBlock(pathKey, tmpBuf, macInputBuf[:fcMacInputLength], resultBuffer)
	//log.Debug("Computing FABRID control validator",
	//	"key", base64.StdEncoding.EncodeToString(PathKey),
	//	"input", base64.StdEncoding.EncodeToString(macInputBuf[:fcMacInputLength]),
	//	"output", base64.StdEncoding.EncodeToString(resultBuffer[:4]))
	if err != nil {
		return err
	}
	return nil
}

func InitFabridControlValidator(fc *ext.FabridControlOption, pathKey []byte) error {
	outBuffer := make([]byte, 16)
	err := computeFabridControlValidator(fc, outBuffer, pathKey)
	if err != nil {
		return err
	}
	outBuffer[0] &= 0xF // ignore first four bits
	log.Debug("Computing FABRID control validator",
		"key", base64.StdEncoding.EncodeToString(pathKey),
		"controlOption", fc,
		"computedValidator", base64.StdEncoding.EncodeToString(outBuffer[:4]))
	copy(fc.Auth[:4], outBuffer[:4])
	return nil
}

func VerifyFabridControlValidator(fc *ext.FabridControlOption, pathKey []byte) error {
	computedValidator := make([]byte, 16)
	err := computeFabridControlValidator(fc, computedValidator, pathKey)
	if err != nil {
		return err
	}
	computedValidator[0] &= 0xF // ignore first four bits
	log.Debug("Verifying FABRID control validator",
		"key", base64.StdEncoding.EncodeToString(pathKey),
		"controlOption", fc,
		"pktValidator", base64.StdEncoding.EncodeToString(fc.Auth[:]),
		"computedValidator", base64.StdEncoding.EncodeToString(computedValidator[:4]))
	if !bytes.Equal(computedValidator[:4], fc.Auth[:]) {
		return serrors.New("Fabrid control validator is not valid")
	}
	return nil
}

var zeroBlock [16]byte

func macBlock(key []byte, tmp []byte, src []byte, dst []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return serrors.WrapStr("unable to initialize AES cipher", err)
	}
	if len(dst) < 16 {
		return serrors.New("Dst length is invalid", "expected", 16, "actual", len(dst))
	}
	if len(src) == 0 {
		return serrors.New("Src length cannot be 0")
	}
	if len(tmp) < 16 {
		return serrors.New("tmp length is invalid", "expected", 16, "actual", len(tmp))
	}
	encryptor := cipher.NewCBCEncrypter(block, zeroBlock[:])
	paddingLength := (16 - len(src)%16) % 16
	blockCount := len(src) / block.BlockSize()

	if blockCount != 0 {
		encryptor.CryptBlocks(dst, src[:16*blockCount])
	}
	if paddingLength != 0 {
		copy(tmp, src[16*blockCount:])
		copy(tmp[16-paddingLength:], zeroBlock[:paddingLength])
		encryptor.CryptBlocks(dst, tmp)
	}
	return nil
}
