/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package cli

import (
	"fmt"

	"github.com/apache/mynewt-artifact/image"
	"github.com/apache/mynewt-artifact/manifest"
	"github.com/apache/mynewt-artifact/mfg"
	"github.com/apache/mynewt-artifact/sec"
)

// Each of these functions verifies one aspect of an image or mfgimage.  They
// return a string containing the result of the check and a bool indicating
// success / failure.

func verifyImageStructureStr(img image.Image) (string, bool) {
	prefix := " structure: "

	if err := img.VerifyStructure(); err != nil {
		return prefix + fmt.Sprintf("BAD (%s)", err.Error()), false
	}

	return prefix + "good", true
}

func verifyImageSigsStr(img image.Image, keys []sec.PubSignKey) (string, bool) {
	prefix := "signatures: "

	sigs, err := img.CollectSigs()
	if err != nil {
		return prefix + fmt.Sprintf("BAD (%s)", err.Error()), false
	}

	if len(sigs) == 0 {
		return prefix + "n/a", true
	}

	if len(keys) == 0 {
		return prefix + "not checked", true
	}

	idx, err := img.VerifySigs(keys)
	if err != nil {
		return prefix + fmt.Sprintf("BAD (%s)", err.Error()), false
	}

	return prefix + fmt.Sprintf("good (%s)", OptSignKeys[idx]), true
}

func verifyImageHashStr(img image.Image, keys []sec.PrivEncKey) (string, bool) {
	prefix := "      hash: "
	if img.IsEncrypted() && len(keys) == 0 {
		return prefix + "not checked (image encrypted; no keys specified)", true
	}

	keyIdx, err := img.VerifyHash(keys)
	if err != nil {
		return prefix + fmt.Sprintf("BAD (%s)", err.Error()), false
	}

	msg := "good"
	if keyIdx != -1 {
		msg += fmt.Sprintf(" (%s)", OptEncKeys[keyIdx])
	}
	return prefix + msg, true
}

func verifyImageManifestStr(img image.Image, man *manifest.Manifest) (string, bool) {
	prefix := "  manifest: "

	if man == nil {
		return prefix + "n/a", true
	}

	if err := img.VerifyManifest(*man); err != nil {
		return prefix + fmt.Sprintf("BAD (%s)", err.Error()), false
	}

	return prefix + "good", true
}

func verifyMfgStructureStr(m mfg.Mfg, man manifest.MfgManifest) (string, bool) {
	prefix := " structure: "

	if err := m.VerifyStructure(man.EraseVal); err != nil {
		return prefix + fmt.Sprintf("BAD (%s)", err.Error()), false
	}

	return prefix + "good", true
}

func verifyMfgSigsStr(m mfg.Mfg, man manifest.MfgManifest, keys []sec.PubSignKey) (string, bool) {
	prefix := "signatures: "

	if len(man.Signatures) == 0 {
		return prefix + "n/a", true
	}

	if len(keys) == 0 {
		return prefix + "not checked", true
	}

	idx, err := mfg.VerifySigs(man, keys)
	if err != nil {
		return prefix + fmt.Sprintf("BAD (%s)", err.Error()), false
	}

	return prefix + fmt.Sprintf("good (%s)", OptSignKeys[idx]), true
}

func verifyMfgManifestStr(m mfg.Mfg, man manifest.MfgManifest) (string, bool) {
	prefix := "  manifest: "

	if err := m.VerifyManifest(man); err != nil {
		return prefix + fmt.Sprintf("BAD (%s)", err.Error()), false
	}

	return prefix + "good", true
}
