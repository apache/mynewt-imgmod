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
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/apache/mynewt-artifact/flash"
	"github.com/apache/mynewt-artifact/manifest"
	"github.com/apache/mynewt-artifact/mfg"
	"github.com/apache/mynewt-artifact/sec"
	"mynewt.apache.org/imgmod/imfg"
	"mynewt.apache.org/imgmod/iutil"
)

const MAX_SIG_LEN = 1024 // Bytes.

func readMfgBin(filename string) ([]byte, error) {
	bin, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read manufacturing image")
	}

	return bin, nil
}

func readManifest(mfgDir string) (manifest.MfgManifest, error) {
	return manifest.ReadMfgManifest(mfgDir + "/" + mfg.MANIFEST_FILENAME)
}

func readMfgDir(mfgDir string) (mfg.Mfg, manifest.MfgManifest, error) {
	man, err := readManifest(mfgDir)
	if err != nil {
		return mfg.Mfg{}, manifest.MfgManifest{}, err
	}

	binPath := fmt.Sprintf("%s/%s", mfgDir, man.BinPath)
	bin, err := readMfgBin(binPath)
	if err != nil {
		return mfg.Mfg{}, manifest.MfgManifest{}, errors.Wrapf(err,
			"failed to read \"%s\"", binPath)
	}

	metaOff := -1
	if man.Meta != nil {
		metaOff = man.Meta.EndOffset
	}
	m, err := mfg.Parse(bin, metaOff, man.EraseVal)
	if err != nil {
		return mfg.Mfg{}, manifest.MfgManifest{}, err
	}

	return m, man, nil
}

func mfgTlvStr(tlv mfg.MetaTlv) string {
	return fmt.Sprintf("%s,0x%02x",
		mfg.MetaTlvTypeName(tlv.Header.Type),
		tlv.Header.Type)
}

func extractFlashAreas(mman manifest.MfgManifest) ([]flash.FlashArea, error) {
	areas := flash.SortFlashAreasByDevOff(mman.FlashAreas)

	if len(areas) == 0 {
		ImgmodUsage(nil, errors.Errorf(
			"Boot loader manifest does not contain flash map"))
	}

	overlaps, conflicts := flash.DetectErrors(areas)
	if len(overlaps) > 0 || len(conflicts) > 0 {
		return nil, errors.New(flash.ErrorText(overlaps, conflicts))
	}

	if err := imfg.VerifyAreas(areas); err != nil {
		return nil, err
	}

	log.Debugf("Successfully read flash areas: %+v", areas)
	return areas, nil
}

func createNameBlobMap(binDir string,
	areas []flash.FlashArea) (imfg.NameBlobMap, error) {

	mm := imfg.NameBlobMap{}

	for _, area := range areas {
		filename := fmt.Sprintf("%s/%s.bin", binDir, area.Name)
		bin, err := readMfgBin(filename)
		if err != nil {
			if !os.IsNotExist(errors.Cause(err)) {
				return nil, errors.Wrapf(err, "could not read mfgimage binary")
			}
		} else {
			mm[area.Name] = bin
		}
	}

	return mm, nil
}

func runMfgShowCmd(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		ImgmodUsage(cmd, nil)
	}
	inFilename := args[0]

	metaEndOff, err := strconv.Atoi(args[1])
	if err != nil {
		ImgmodUsage(cmd, errors.Errorf("invalid meta offset \"%s\"", args[1]))
	}

	bin, err := readMfgBin(inFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	m, err := mfg.Parse(bin, metaEndOff, 0xff)
	if err != nil {
		ImgmodUsage(nil, err)
	}

	if m.Meta == nil {
		iutil.Printf("Manufacturing image %s does not contain an MMR\n",
			inFilename)
	} else {
		s, err := m.Meta.Json(metaEndOff)
		if err != nil {
			ImgmodUsage(nil, err)
		}
		iutil.Printf("Manufacturing image %s contains an MMR with "+
			"the following properties:\n%s\n", inFilename, s)
	}
}

func runSplitCmd(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		ImgmodUsage(cmd, nil)
	}

	mfgDir := args[0]
	outDir := args[1]

	m, man, err := readMfgDir(mfgDir)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	bin, err := m.Bytes(man.EraseVal)
	if err != nil {
		ImgmodUsage(nil, err)
	}

	areas, err := extractFlashAreas(man)
	if err != nil {
		ImgmodUsage(nil, err)
	}

	nbmap, err := imfg.Split(bin, man.Device, areas, man.EraseVal)
	if err != nil {
		ImgmodUsage(nil, err)
	}

	if err := os.Mkdir(outDir, os.ModePerm); err != nil {
		ImgmodUsage(nil, errors.Wrapf(err, "failed to make output directory"))
	}

	for name, data := range nbmap {
		filename := fmt.Sprintf("%s/%s.bin", outDir, name)
		if err := WriteFile(data, filename); err != nil {
			ImgmodUsage(nil, err)
		}
	}

	mfgDstDir := fmt.Sprintf("%s/mfg", outDir)
	if err := CopyDir(mfgDir, mfgDstDir); err != nil {
		ImgmodUsage(nil, err)
	}
}

func runJoinCmd(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		ImgmodUsage(cmd, nil)
	}

	splitDir := args[0]
	outDir := args[1]

	mm, err := readManifest(splitDir + "/mfg")
	if err != nil {
		ImgmodUsage(cmd, err)
	}
	areas, err := extractFlashAreas(mm)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	nbmap, err := createNameBlobMap(splitDir, areas)
	if err != nil {
		ImgmodUsage(nil, err)
	}

	bin, err := imfg.Join(nbmap, mm.EraseVal, areas)
	if err != nil {
		ImgmodUsage(nil, err)
	}

	m, err := mfg.Parse(bin, mm.Meta.EndOffset, mm.EraseVal)
	if err != nil {
		ImgmodUsage(nil, err)
	}

	infos, err := ioutil.ReadDir(splitDir + "/mfg")
	if err != nil {
		ImgmodUsage(nil, errors.Wrapf(err,
			"Error reading source mfg directory: %s"))
	}
	for _, info := range infos {
		if info.Name() != mfg.MFG_BIN_IMG_FILENAME {
			src := splitDir + "/mfg/" + info.Name()
			dst := outDir + "/" + info.Name()
			if info.IsDir() {
				err = CopyDir(src, dst)
			} else {
				err = CopyFile(src, dst)
			}
			if err != nil {
				ImgmodUsage(nil, err)
			}
		}
	}

	finalBin, err := m.Bytes(mm.EraseVal)
	if err != nil {
		ImgmodUsage(nil, err)
	}

	binPath := fmt.Sprintf("%s/%s", outDir, mfg.MFG_BIN_IMG_FILENAME)
	if err := WriteFile(finalBin, binPath); err != nil {
		ImgmodUsage(nil, err)
	}
}

func genSwapKeyCmd(cmd *cobra.Command, args []string, isKek bool) {
	if len(args) < 3 {
		ImgmodUsage(cmd, nil)
	}

	mfgimgFilename := args[0]
	okeyFilename := args[1]
	nkeyFilename := args[2]

	outFilename, err := CalcOutFilename(mfgimgFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	bin, err := readMfgBin(mfgimgFilename)
	if err != nil {
		ImgmodUsage(cmd, errors.Wrapf(err,
			"failed to read mfgimg file: %s"))
	}

	okey, err := ioutil.ReadFile(okeyFilename)
	if err != nil {
		ImgmodUsage(cmd, errors.Wrapf(err, "failed to read old key der: %s"))
	}

	nkey, err := ioutil.ReadFile(nkeyFilename)
	if err != nil {
		ImgmodUsage(cmd, errors.Wrapf(err, "failed to read new key der: %s"))
	}

	if isKek {
		err = imfg.ReplaceKek(bin, okey, nkey)
	} else {
		err = imfg.ReplaceIsk(bin, okey, nkey)
	}
	if err != nil {
		ImgmodUsage(nil, err)
	}

	if err := WriteFile(bin, outFilename); err != nil {
		ImgmodUsage(nil, err)
	}
}

func runSwapIskCmd(cmd *cobra.Command, args []string) {
	genSwapKeyCmd(cmd, args, false)
}

func runSwapKekCmd(cmd *cobra.Command, args []string) {
	genSwapKeyCmd(cmd, args, true)
}

func runMfgHashableCmd(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		ImgmodUsage(cmd, nil)
	}

	if OptOutFilename == "" {
		ImgmodUsage(cmd, errors.Errorf("--outfile (-o) option required"))
	}

	mfgDir := args[0]
	outFilename := OptOutFilename

	m, man, err := readMfgDir(mfgDir)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	// Zero-out hash so that the hash can be recalculated.
	if m.Meta != nil {
		m.Meta.ClearHash()
	}

	// Write hashable content to disk.
	newBin, err := m.Bytes(man.EraseVal)
	if err != nil {
		ImgmodUsage(nil, err)
	}
	if err := WriteFile(newBin, outFilename); err != nil {
		ImgmodUsage(nil, err)
	}
}

func runRehashCmd(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		ImgmodUsage(cmd, nil)
	}

	mfgDir := args[0]

	outDir, err := CalcOutFilename(mfgDir)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	m, man, err := readMfgDir(mfgDir)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	if err := m.RefillHash(man.EraseVal); err != nil {
		ImgmodUsage(nil, err)
	}

	hash, err := m.Hash(man.EraseVal)
	if err != nil {
		ImgmodUsage(nil, err)
	}

	// Update manifest.
	man.MfgHash = hex.EncodeToString(hash)

	// Write new artifacts.
	if err := EnsureOutDir(mfgDir, outDir); err != nil {
		ImgmodUsage(nil, err)
	}
	binPath := fmt.Sprintf("%s/%s", outDir, man.BinPath)

	newBin, err := m.Bytes(man.EraseVal)
	if err != nil {
		ImgmodUsage(nil, err)
	}
	if err := WriteFile(newBin, binPath); err != nil {
		ImgmodUsage(nil, err)
	}

	json, err := man.MarshalJson()
	if err != nil {
		ImgmodUsage(nil, err)
	}

	manPath := fmt.Sprintf("%s/%s", outDir, mfg.MANIFEST_FILENAME)
	if err := WriteFile(json, manPath); err != nil {
		ImgmodUsage(nil, err)
	}
}

func runRmsigsMfgCmd(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		ImgmodUsage(cmd, nil)
	}

	mfgDir := args[0]

	outDir, err := CalcOutFilename(mfgDir)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	// Read manifest.
	mman, err := readManifest(mfgDir)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	// Update manifest.
	mman.Signatures = nil

	// Write new artifacts.
	if err := EnsureOutDir(mfgDir, outDir); err != nil {
		ImgmodUsage(nil, err)
	}

	json, err := mman.MarshalJson()
	if err != nil {
		ImgmodUsage(nil, err)
	}

	manPath := fmt.Sprintf("%s/%s", outDir, mfg.MANIFEST_FILENAME)
	if err := WriteFile(json, manPath); err != nil {
		ImgmodUsage(nil, err)
	}
}

func runAddsigMfgCmd(cmd *cobra.Command, args []string) {
	if len(args) < 3 {
		ImgmodUsage(cmd, nil)
	}

	mfgDir := args[0]
	keyFilename := args[1]
	sigFilename := args[2]

	outDir, err := CalcOutFilename(mfgDir)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	// Read manifest.
	mman, err := readManifest(mfgDir)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	// Read public key.
	keyBytes, err := ioutil.ReadFile(keyFilename)
	if err != nil {
		ImgmodUsage(cmd, errors.Wrapf(err, "error reading key file"))
	}

	// Read signature.
	sig, err := ioutil.ReadFile(sigFilename)
	if err != nil {
		ImgmodUsage(cmd, errors.Wrapf(err, "failed to read signature"))
	}
	if len(sig) > MAX_SIG_LEN {
		ImgmodUsage(nil, errors.Errorf(
			"signature larger than arbitrary maximum length (%d > %d)",
			len(sig), MAX_SIG_LEN))
	}

	// Update manifest.
	mman.Signatures = append(mman.Signatures, manifest.MfgManifestSig{
		Key: hex.EncodeToString(sec.RawKeyHash(keyBytes)),
		Sig: hex.EncodeToString(sig),
	})

	// Write new artifacts.
	if err := EnsureOutDir(mfgDir, outDir); err != nil {
		ImgmodUsage(nil, err)
	}

	json, err := mman.MarshalJson()
	if err != nil {
		ImgmodUsage(nil, err)
	}

	manPath := fmt.Sprintf("%s/%s", outDir, mfg.MANIFEST_FILENAME)
	if err := WriteFile(json, manPath); err != nil {
		ImgmodUsage(nil, err)
	}
}

func runRmtlvsMfgCmd(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		ImgmodUsage(cmd, nil)
	}

	mfgDir := args[0]

	outFilename, err := CalcOutFilename(
		mfgDir + "/" + mfg.MFG_BIN_IMG_FILENAME)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	m, man, err := readMfgDir(mfgDir)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	numTlvs := 0
	if m.Meta != nil {
		numTlvs = len(m.Meta.Tlvs)
	}

	tlvIndices := []int{}
	idxMap := map[int]struct{}{}
	for _, arg := range args[1:] {
		idx, err := strconv.Atoi(arg)
		if err != nil {
			ImgmodUsage(cmd, errors.Errorf("invalid TLV index: %s", arg))
		}

		if idx < 0 || idx >= numTlvs {
			ImgmodUsage(nil, errors.Errorf(
				"TLV index %s out of range; "+
					"must be in range [0, %d] for this mfgimage",
				arg, numTlvs-1))
		}

		if _, ok := idxMap[idx]; ok {
			ImgmodUsage(nil, errors.Errorf(
				"TLV index %d specified more than once", idx))
		}
		idxMap[idx] = struct{}{}

		tlvIndices = append(tlvIndices, idx)
	}

	// Remove TLVs in reverse order to preserve index mapping.
	sort.Sort(sort.Reverse(sort.IntSlice(tlvIndices)))
	for _, idx := range tlvIndices {
		tlv := m.Meta.Tlvs[idx]
		iutil.Printf("Removing TLV%d: %s\n", idx, mfgTlvStr(tlv))

		tlvSz := mfg.META_TLV_HEADER_SZ + len(tlv.Data)
		m.MetaOff += tlvSz
		m.Meta.Footer.Size -= uint16(tlvSz)

		m.Meta.Tlvs = append(m.Meta.Tlvs[0:idx], m.Meta.Tlvs[idx+1:]...)
	}

	// Rehash.
	if err := m.RefillHash(man.EraseVal); err != nil {
		ImgmodUsage(nil, err)
	}

	// Write new artifacts.
	newBin, err := m.Bytes(man.EraseVal)
	if err != nil {
		ImgmodUsage(nil, err)
	}
	if err := WriteFile(newBin, outFilename); err != nil {
		ImgmodUsage(nil, err)
	}
}

func verifyEmbeddedImages(m mfg.Mfg, man manifest.MfgManifest, iss []sec.PubSignKey, kes []sec.PrivEncKey) (string, bool) {
	prefix := "    images: "
	good := true

	imgs, err := m.ExtractImages(man)
	if err != nil {
		return prefix + fmt.Sprintf("BAD (%s)", err.Error()), false
	}

	var results [][]string
	for _, img := range imgs {
		st, stgood := verifyImageStructureStr(img)
		ha, hagood := verifyImageHashStr(img, kes)
		si, sigood := verifyImageSigsStr(img, iss)

		results = append(results, []string{
			st, ha, si,
		})

		if !stgood || !hagood || !sigood {
			good = false
		}
	}

	sub := "\n"
	for i, r := range results {
		if i != 0 {
			sub += "\n"
		}

		sub += Indent(fmt.Sprintf("%d:\n", i), 12)
		sub += strings.Join(IndentLines(r, 16), "\n")
	}

	return prefix + sub, good
}

func runVerifyMfgCmd(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		ImgmodUsage(cmd, nil)
	}

	mfgDir := args[0]

	// Read mfgimg.bin and manifest.
	m, man, err := readMfgDir(mfgDir)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	iss, err := sec.ReadPubSignKeys(OptSignKeys)
	if err != nil {
		ImgmodUsage(nil, errors.Wrapf(err, "error reading signing key file"))
	}

	kes, err := sec.ReadPrivEncKeys(OptEncKeys)
	if err != nil {
		ImgmodUsage(nil, errors.Wrapf(err,
			"error reading encryption key file"))
	}

	st, stgood := verifyMfgStructureStr(m, man)
	si, sigood := verifyMfgSigsStr(m, man, iss)
	ma, magood := verifyMfgManifestStr(m, man)

	im := ""
	imgood := true
	if OptVerifyImages {
		im, imgood = verifyEmbeddedImages(m, man, iss, kes)
	} else {
		im = "    images: n/a"
	}

	iutil.Printf("%s\n", st)
	iutil.Printf("%s\n", si)
	iutil.Printf("%s\n", ma)
	iutil.Printf("%s\n", im)

	if !stgood || !sigood || !magood || !imgood {
		os.Exit(94) // EBADMSG
	}
}

func AddMfgCommands(cmd *cobra.Command) {
	mfgCmd := &cobra.Command{
		Use:   "mfg",
		Short: "Manipulates Mynewt manufacturing images",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Usage()
		},
	}
	cmd.AddCommand(mfgCmd)

	showCmd := &cobra.Command{
		Use:   "show <mfgimg.bin> <meta-end-offset>",
		Short: "Displays JSON describing a manufacturing image",
		Run:   runMfgShowCmd,
	}

	mfgCmd.AddCommand(showCmd)

	splitCmd := &cobra.Command{
		Use:   "split <mfgimage-dir> <out-dir>",
		Short: "Splits a Mynewt mfg section into several files",
		Run:   runSplitCmd,
	}

	mfgCmd.AddCommand(splitCmd)

	joinCmd := &cobra.Command{
		Use:   "join <split-dir> <out-dir>",
		Short: "Joins a split mfg section into a single file",
		Run:   runJoinCmd,
	}

	mfgCmd.AddCommand(joinCmd)

	swapIskCmd := &cobra.Command{
		Use:   "swapisk <mfgimg-bin> <cur-key-der> <new-key-der>",
		Short: "Replaces an image-signing key in a manufacturing image",
		Run:   runSwapIskCmd,
	}

	swapIskCmd.PersistentFlags().StringVarP(&OptOutFilename, "outfile", "o",
		"", "File to write to")
	swapIskCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input file")

	mfgCmd.AddCommand(swapIskCmd)

	swapKekCmd := &cobra.Command{
		Use:   "swapkek <mfgimg-bin> <cur-key-der> <new-key-der>",
		Short: "Replaces a key-encrypting key in a manufacturing image",
		Run:   runSwapKekCmd,
	}

	swapKekCmd.PersistentFlags().StringVarP(&OptOutFilename, "outfile", "o",
		"", "File to write to")
	swapKekCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input file")

	mfgCmd.AddCommand(swapKekCmd)

	hashableCmd := &cobra.Command{
		Use:   "hashable <mfgimage-dir>",
		Short: "Extracts the hashable / signable content of an mfgimage",
		Run:   runMfgHashableCmd,
	}
	hashableCmd.PersistentFlags().StringVarP(&OptOutFilename, "outfile", "o",
		"", "File to write to")

	mfgCmd.AddCommand(hashableCmd)

	rehashCmd := &cobra.Command{
		Use:   "rehash <mfgimage-dir>",
		Short: "Replaces an outdated mfgimage hash with an accurate one",
		Run:   runRehashCmd,
	}
	rehashCmd.PersistentFlags().StringVarP(&OptOutFilename, "outdir", "o",
		"", "Directory to write to")
	rehashCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input files")

	mfgCmd.AddCommand(rehashCmd)

	rmsigsCmd := &cobra.Command{
		Use:   "rmsigs <mfgimage-dir>",
		Short: "Removes all signatures from an mfgimage's manifest",
		Run:   runRmsigsMfgCmd,
	}
	rmsigsCmd.PersistentFlags().StringVarP(&OptOutFilename, "outdir", "o",
		"", "Directory to write to")
	rmsigsCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input files")

	mfgCmd.AddCommand(rmsigsCmd)

	addsigCmd := &cobra.Command{
		Use:   "addsig <mfgimage-dir> <pub-key-der> <sig-der>",
		Short: "Adds a signature to an mfgimage's manifest",
		Run:   runAddsigMfgCmd,
	}
	addsigCmd.PersistentFlags().StringVarP(&OptOutFilename, "outdir", "o",
		"", "Directory to write to")
	addsigCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input files")

	mfgCmd.AddCommand(addsigCmd)

	rmtlvsCmd := &cobra.Command{
		Use:   "rmtlvs <mfgimage-dir> <tlv-index> [tlv-index] [...]",
		Short: "Removes the specified TLVs from a Mynewt mfgimage",
		Run:   runRmtlvsMfgCmd,
	}

	rmtlvsCmd.PersistentFlags().StringVarP(&OptOutFilename, "outfile", "o", "",
		"File to write to")
	rmtlvsCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input file")

	mfgCmd.AddCommand(rmtlvsCmd)

	verifyCmd := &cobra.Command{
		Use:   "verify <mfgimage-dir>",
		Short: "Verifies an Mynewt mfgimage's integrity",
		Run:   runVerifyMfgCmd,
	}

	verifyCmd.PersistentFlags().BoolVar(&OptVerifyImages, "images", false,
		"Verify embedded images")
	verifyCmd.PersistentFlags().StringSliceVar(&OptSignKeys, "signkey",
		nil, "Public signing key (.pem) (can be repeated)")
	verifyCmd.PersistentFlags().StringSliceVar(&OptEncKeys, "enckey",
		nil, "Private encryption key (.der) (can be repeated)")

	mfgCmd.AddCommand(verifyCmd)
}
