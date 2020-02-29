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
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/apache/mynewt-artifact/errors"
	"github.com/apache/mynewt-artifact/image"
	"github.com/apache/mynewt-artifact/manifest"
	"github.com/apache/mynewt-artifact/sec"
	"mynewt.apache.org/imgmod/iimg"
	"mynewt.apache.org/imgmod/iutil"
)

func tlvStr(tlv image.ImageTlv) string {
	return fmt.Sprintf("%s,0x%02x",
		image.ImageTlvTypeName(tlv.Header.Type),
		tlv.Header.Type)
}

func readImage(filename string) (image.Image, error) {
	img, err := image.ReadImage(filename)
	if err != nil {
		return img, err
	}

	log.Debugf("Successfully read image %s", filename)
	return img, nil
}

func writeImage(img image.Image, filename string) error {
	if err := iimg.VerifyImage(img); err != nil {
		return err
	}

	if err := img.WriteToFile(filename); err != nil {
		return err
	}

	iutil.Printf("Wrote image %s\n", filename)
	return nil
}

func parseTlvArgs(typeArg string, filenameArg string) (image.ImageTlv, error) {
	tlvType, err := strconv.Atoi(typeArg)
	if err != nil || tlvType < 0 {
		return image.ImageTlv{}, errors.Errorf(
			"invalid TLV type integer: %s", typeArg)
	}

	data, err := ioutil.ReadFile(filenameArg)
	if err != nil {
		return image.ImageTlv{}, errors.Wrapf(err,
			"error reading TLV data file")
	}

	return image.ImageTlv{
		Header: image.ImageTlvHdr{
			Type: uint8(tlvType),
			Pad:  0,
			Len:  uint16(len(data)),
		},
		Data: data,
	}, nil
}

func runShowCmd(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		ImgmodUsage(cmd, nil)
	}

	img, err := readImage(args[0])
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	s, err := img.Json()
	if err != nil {
		ImgmodUsage(nil, err)
	}
	iutil.Printf("%s\n", s)
}

func runBriefCmd(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		ImgmodUsage(cmd, nil)
	}

	img, err := readImage(args[0])
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	offsets, err := img.Offsets()
	if err != nil {
		ImgmodUsage(nil, err)
	}

	iutil.Printf("%8d| Header\n", offsets.Header)
	iutil.Printf("%8d| Body\n", offsets.Body)
	iutil.Printf("%8d| Trailer\n", offsets.Trailer)
	for i, tlv := range img.Tlvs {
		iutil.Printf("%8d| TLV%d: type=%s(%d)\n",
			offsets.Tlvs[i], i, image.ImageTlvTypeName(tlv.Header.Type),
			tlv.Header.Type)
	}
	iutil.Printf("Total=%d\n", offsets.TotalSize)
}

func runSignCmd(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		ImgmodUsage(cmd, nil)
	}

	inFilename := args[0]
	outFilename, err := CalcOutFilename(inFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	img, err := readImage(inFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	keys, err := sec.ReadPrivSignKeys(args[1:])
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	hash, err := img.Hash()
	if err != nil {
		ImgmodUsage(cmd, errors.Wrapf(err,
			"failed to read hash from specified image"))
	}

	tlvs, err := image.BuildSigTlvs(keys, hash)
	if err != nil {
		ImgmodUsage(nil, err)
	}

	img.Tlvs = append(img.Tlvs, tlvs...)

	if err := writeImage(img, outFilename); err != nil {
		ImgmodUsage(nil, err)
	}
}

func runAddTlvsCmd(cmd *cobra.Command, args []string) {
	if len(args) < 3 {
		ImgmodUsage(cmd, nil)
	}

	inFilename := args[0]
	outFilename, err := CalcOutFilename(inFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	img, err := readImage(inFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	tlvArgs := args[1:]
	if len(tlvArgs)%2 != 0 {
		ImgmodUsage(cmd, errors.Errorf(
			"invalid argument count; each TLV requires two arguments"))
	}

	tlvs := []image.ImageTlv{}
	for i := 0; i < len(tlvArgs); i += 2 {
		tlv, err := parseTlvArgs(tlvArgs[i], tlvArgs[i+1])
		if err != nil {
			ImgmodUsage(cmd, err)
		}

		tlvs = append(tlvs, tlv)
	}

	img.Tlvs = append(img.Tlvs, tlvs...)

	if err := writeImage(img, outFilename); err != nil {
		ImgmodUsage(nil, err)
	}
}

func runRmtlvsCmd(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		ImgmodUsage(cmd, nil)
	}

	inFilename := args[0]
	outFilename, err := CalcOutFilename(inFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	img, err := readImage(inFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	tlvIndices := []int{}
	idxMap := map[int]struct{}{}
	for _, arg := range args[1:] {
		idx, err := strconv.Atoi(arg)
		if err != nil {
			ImgmodUsage(cmd, errors.Errorf("invalid TLV index: %s", arg))
		}

		if idx < 0 || idx >= len(img.Tlvs) {
			ImgmodUsage(nil, errors.Errorf(
				"TLV index %s out of range; "+
					"must be in range [0, %d] for this image",
				arg, len(img.Tlvs)-1))
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
		tlv := img.Tlvs[idx]
		iutil.Printf("Removing TLV%d: %s\n", idx, tlvStr(tlv))

		img.Tlvs = append(img.Tlvs[0:idx], img.Tlvs[idx+1:]...)
	}

	if err := writeImage(img, outFilename); err != nil {
		ImgmodUsage(nil, err)
	}
}

func runRmsigsCmd(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		ImgmodUsage(cmd, nil)
	}

	inFilename := args[0]
	outFilename, err := CalcOutFilename(inFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	img, err := readImage(inFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	cnt := img.RemoveTlvsIf(func(tlv image.ImageTlv) bool {
		return tlv.Header.Type == image.IMAGE_TLV_KEYHASH ||
			tlv.Header.Type == image.IMAGE_TLV_RSA2048 ||
			tlv.Header.Type == image.IMAGE_TLV_ECDSA224 ||
			tlv.Header.Type == image.IMAGE_TLV_ECDSA256
	})

	log.Debugf("Removed %d existing signatures", cnt)

	if err := writeImage(img, outFilename); err != nil {
		ImgmodUsage(nil, err)
	}
}

func runHashableCmd(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		ImgmodUsage(cmd, nil)
	}

	if OptOutFilename == "" {
		ImgmodUsage(cmd, errors.Errorf("--outfile (-o) option required"))
	}

	inFilename := args[0]
	outFilename := OptOutFilename

	img, err := readImage(inFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	if (img.Header.Flags & image.IMAGE_F_ENCRYPTED) != 0 {
		fmt.Fprintf(os.Stderr,
			"* Warning: extracting hashable content from an encrypted image\n")
	}

	f, err := os.Create(outFilename)
	if err != nil {
		ImgmodUsage(nil, errors.Wrapf(err, "failed to create hashable output"))
	}
	defer f.Close()

	if err := binary.Write(f, binary.LittleEndian, &img.Header); err != nil {
		ImgmodUsage(nil, errors.Wrapf(err, "error writing image header"))
	}
	_, err = f.Write(img.Body)
	if err != nil {
		ImgmodUsage(nil, errors.Wrapf(err, "error writing image body"))
	}

	iutil.Printf("Wrote hashable content to %s\n", outFilename)
}

func runAddsigCmd(cmd *cobra.Command, args []string) {
	if len(args) < 4 {
		ImgmodUsage(cmd, nil)
	}

	imgFilename := args[0]
	keyFilename := args[1]
	sigFilename := args[2]

	sigType, err := strconv.Atoi(args[3])
	if err != nil || sigType < 0 || sigType > 255 ||
		!image.ImageTlvTypeIsSig(uint8(sigType)) {

		ImgmodUsage(cmd, errors.Errorf("invalid signature type: %s", args[3]))
	}

	outFilename, err := CalcOutFilename(imgFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	img, err := readImage(imgFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	keyData, err := ioutil.ReadFile(keyFilename)
	if err != nil {
		ImgmodUsage(cmd, errors.Wrapf(err, "error reading key file"))
	}

	sigData, err := ioutil.ReadFile(sigFilename)
	if err != nil {
		ImgmodUsage(cmd, errors.Wrapf(err, "error reading signature file"))
	}

	// ECDSA256 signatures need to be padded out to >=72 bytes.
	if sigType == image.IMAGE_TLV_ECDSA256 {
		sigData, err = iimg.PadEcdsa256Sig(sigData)
		if err != nil {
			ImgmodUsage(nil, err)
		}
	}

	// Build and append key hash TLV.
	keyHashTlv := image.BuildKeyHashTlv(keyData)
	iutil.Printf("Adding TLV%d (%s)\n", len(img.Tlvs), tlvStr(keyHashTlv))
	img.Tlvs = append(img.Tlvs, keyHashTlv)

	// Build and append signature TLV.
	sigTlv := image.ImageTlv{
		Header: image.ImageTlvHdr{
			Type: uint8(sigType),
			Len:  uint16(len(sigData)),
		},
		Data: sigData,
	}
	iutil.Printf("Adding TLV%d (%s)\n", len(img.Tlvs), tlvStr(sigTlv))
	img.Tlvs = append(img.Tlvs, sigTlv)

	if err := writeImage(img, outFilename); err != nil {
		ImgmodUsage(nil, err)
	}
}

func runDecryptCmd(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		ImgmodUsage(cmd, nil)
	}

	imgFilename := args[0]
	keyFilename := args[1]

	outFilename, err := CalcOutFilename(imgFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	img, err := readImage(imgFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	keyBytes, err := ioutil.ReadFile(keyFilename)
	if err != nil {
		ImgmodUsage(cmd, errors.Wrapf(err, "error reading key file"))
	}

	img, err = iimg.DecryptImage(img, keyBytes)
	if err != nil {
		ImgmodUsage(nil, err)
	}

	if err := writeImage(img, outFilename); err != nil {
		ImgmodUsage(nil, err)
	}
}

func runDecryptFullCmd(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		ImgmodUsage(cmd, nil)
	}

	imgFilename := args[0]
	keyFilename := args[1]

	outFilename, err := CalcOutFilename(imgFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	img, err := readImage(imgFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	keyBytes, err := ioutil.ReadFile(keyFilename)
	if err != nil {
		ImgmodUsage(cmd, errors.Wrapf(err, "error reading key file"))
	}

	img, err = iimg.DecryptImageFull(img, keyBytes)
	if err != nil {
		ImgmodUsage(nil, err)
	}
	if err := writeImage(img, outFilename); err != nil {
		ImgmodUsage(nil, err)
	}
}

func runEncryptCmd(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		ImgmodUsage(cmd, nil)
	}

	imgFilename := args[0]
	keyFilename := args[1]

	outFilename, err := CalcOutFilename(imgFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	img, err := readImage(imgFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	keyBytes, err := ioutil.ReadFile(keyFilename)
	if err != nil {
		ImgmodUsage(cmd, errors.Wrapf(err, "error reading key file"))
	}

	img, err = iimg.EncryptImage(img, keyBytes)
	if err != nil {
		ImgmodUsage(nil, err)
	}

	if err := writeImage(img, outFilename); err != nil {
		ImgmodUsage(nil, err)
	}
}

func runEncryptFullCmd(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		ImgmodUsage(cmd, nil)
	}

	imgFilename := args[0]
	keyFilename := args[1]

	outFilename, err := CalcOutFilename(imgFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	img, err := readImage(imgFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	keyBytes, err := ioutil.ReadFile(keyFilename)
	if err != nil {
		ImgmodUsage(cmd, errors.Wrapf(err, "error reading key file"))
	}

	img, err = iimg.EncryptImageFull(img, keyBytes)
	if err != nil {
		ImgmodUsage(nil, err)
	}

	if err := writeImage(img, outFilename); err != nil {
		ImgmodUsage(nil, err)
	}
}

func runVerifyCmd(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		ImgmodUsage(cmd, nil)
	}

	imgFilename := args[0]

	img, err := readImage(imgFilename)
	if err != nil {
		ImgmodUsage(cmd, err)
	}

	kes, err := sec.ReadPrivEncKeys(OptEncKeys)
	if err != nil {
		ImgmodUsage(nil, errors.Wrapf(err,
			"error reading encryption key file"))
	}

	iss, err := sec.ReadPubSignKeys(OptSignKeys)
	if err != nil {
		ImgmodUsage(nil, errors.Wrapf(err, "error reading signing key file"))
	}

	var man *manifest.Manifest
	if OptManifest != "" {
		mfest, err := manifest.ReadManifest(OptManifest)
		if err != nil {
			ImgmodUsage(nil, err)
		}
		man = &mfest
	}

	st, stgood := verifyImageStructureStr(img)
	ha, hagood := verifyImageHashStr(img, kes)
	si, sigood := verifyImageSigsStr(img, iss)
	ma, magood := verifyImageManifestStr(img, man)

	iutil.Printf("%s\n", st)
	iutil.Printf("%s\n", ha)
	iutil.Printf("%s\n", si)
	iutil.Printf("%s\n", ma)

	if !stgood || !hagood || !sigood || !magood {
		os.Exit(94) // EBADMSG
	}
}

func AddImageCommands(cmd *cobra.Command) {
	imageCmd := &cobra.Command{
		Use:   "image",
		Short: "Shows and manipulates Mynewt image (.img) files",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Usage()
		},
	}
	cmd.AddCommand(imageCmd)

	showCmd := &cobra.Command{
		Use:   "show <img-file>",
		Short: "Displays JSON describing a Mynewt image file",
		Run:   runShowCmd,
	}
	imageCmd.AddCommand(showCmd)

	briefCmd := &cobra.Command{
		Use:   "brief <img-file>",
		Short: "Displays brief text description of a Mynewt image file",
		Run:   runBriefCmd,
	}
	imageCmd.AddCommand(briefCmd)

	signCmd := &cobra.Command{
		Use:   "sign <img-file> <priv-key-pem> [priv-key-pem...]",
		Short: "Appends signatures to a Mynewt image file",
		Run:   runSignCmd,
	}

	signCmd.PersistentFlags().StringVarP(&OptOutFilename, "outfile", "o", "",
		"File to write to")
	signCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input file")

	imageCmd.AddCommand(signCmd)

	addTlvsCmd := &cobra.Command{
		Use: "addtlvs <img-file> <tlv-type> <data-filename> " +
			"[tlv-type] [data-filename] [...]",
		Short: "Adds the specified TLVs to a Mynewt image file",
		Run:   runAddTlvsCmd,
	}

	addTlvsCmd.PersistentFlags().StringVarP(&OptOutFilename, "outfile", "o", "",
		"File to write to")
	addTlvsCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input file")

	imageCmd.AddCommand(addTlvsCmd)

	rmtlvsCmd := &cobra.Command{
		Use:   "rmtlvs <img-file> <tlv-index> [tlv-index] [...]",
		Short: "Removes the specified TLVs from a Mynewt image file",
		Run:   runRmtlvsCmd,
	}

	rmtlvsCmd.PersistentFlags().StringVarP(&OptOutFilename, "outfile", "o", "",
		"File to write to")
	rmtlvsCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input file")

	imageCmd.AddCommand(rmtlvsCmd)

	rmsigsCmd := &cobra.Command{
		Use:   "rmsigs",
		Short: "Removes all signatures from a Mynewt image file",
		Run:   runRmsigsCmd,
	}

	rmsigsCmd.PersistentFlags().StringVarP(&OptOutFilename, "outfile", "o", "",
		"File to write to")
	rmsigsCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input file")

	imageCmd.AddCommand(rmsigsCmd)

	hashableCmd := &cobra.Command{
		Use:   "hashable <img-file>",
		Short: "Extracts an image's hashable content",
		Run:   runHashableCmd,
	}

	hashableCmd.PersistentFlags().StringVarP(&OptOutFilename, "outfile", "o",
		"", "File to write to")

	imageCmd.AddCommand(hashableCmd)

	addsigCmd := &cobra.Command{
		Use:   "addsig <image> <pub-key-der> <sig-der> <sig-tlv-type>",
		Short: "Adds a signature to a Mynewt image file",
		Run:   runAddsigCmd,
	}

	addsigCmd.PersistentFlags().StringVarP(&OptOutFilename, "outfile", "o",
		"", "File to write to")
	addsigCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input file")

	imageCmd.AddCommand(addsigCmd)

	decryptCmd := &cobra.Command{
		Use:   "decrypt <image> <priv-key-der>",
		Short: "Decrypts an encrypted Mynewt image file (partial)",
		Long: "Decrypts the body of an encrypted Mynewt image file and " +
			"removes the encryption TLVs.  This command does not change the " +
			"image header and does not recalculate the image hash.  This " +
			"command is useful for re-signing an image with a new key prior " +
			"to re-encrypting.",
		Run: runDecryptCmd,
	}

	decryptCmd.PersistentFlags().StringVarP(&OptOutFilename, "outfile", "o",
		"", "File to write to")
	decryptCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input file")

	imageCmd.AddCommand(decryptCmd)

	decryptFullCmd := &cobra.Command{
		Use:   "decryptfull <image> <priv-key-der>",
		Short: "Decrypts an encrypted Mynewt image file (full)",
		Long: "Decrypts the body of an encrypted Mynewt image file, " +
			"removes the encryption TLVs, clears the 'encrypted' flag in " +
			"the image header, and recalculates the image hash.",
		Run: runDecryptFullCmd,
	}

	decryptFullCmd.PersistentFlags().StringVarP(&OptOutFilename, "outfile", "o",
		"", "File to write to")
	decryptFullCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input file")

	imageCmd.AddCommand(decryptFullCmd)

	encryptCmd := &cobra.Command{
		Use:   "encrypt <image> <priv-key-der>",
		Short: "Encrypts a Mynewt image file",
		Long: "Encrypts the body of an encrypted Mynewt image file and " +
			"adds encryption TLVs.  This command does not change the " +
			"image header and does not recalculate the image hash.",
		Run: runEncryptCmd,
	}

	encryptCmd.PersistentFlags().StringVarP(&OptOutFilename, "outfile", "o",
		"", "File to write to")
	encryptCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input file")

	imageCmd.AddCommand(encryptCmd)

	encryptFullCmd := &cobra.Command{
		Use:   "encryptfull <image> <priv-key-der>",
		Short: "Encrypts an encrypted Mynewt image file (full)",
		Long: "Encrypts the body of an encrypted Mynewt image file, " +
			"adds encryption TLVs, sets the 'encrypted' flag in " +
			"the image header, and recalculates the image hash.",
		Run: runEncryptFullCmd,
	}

	encryptFullCmd.PersistentFlags().StringVarP(&OptOutFilename, "outfile", "o",
		"", "File to write to")
	encryptFullCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input file")

	imageCmd.AddCommand(encryptFullCmd)

	verifyCmd := &cobra.Command{
		Use:   "verify <image>",
		Short: "Verifies an Mynewt image's integrity",
		Run:   runVerifyCmd,
	}

	verifyCmd.PersistentFlags().StringSliceVar(&OptSignKeys, "signkey",
		nil, "Public signing key (.pem) (can be repeated)")
	verifyCmd.PersistentFlags().StringSliceVar(&OptEncKeys, "enckey",
		nil, "Private encryption key (.der) (can be repeated)")
	verifyCmd.PersistentFlags().StringVar(&OptManifest, "manifest",
		"", "Manifest file")

	imageCmd.AddCommand(verifyCmd)
}
