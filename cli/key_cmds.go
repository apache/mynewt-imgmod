package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/apache/mynewt-artifact/errors"
	"github.com/spf13/cobra"

	"mynewt.apache.org/imgmod/ikey"
)

func keyDescToJson(path string, body []byte, desc ikey.Desc) (string, error) {
	type Key struct {
		Path       string `json:"path"`
		Type       string `json:"type"`
		Algorithm  string `json:"algorithm"`
		Hash       string `json:"hash"`
		FileSha256 string `json:"file_sha256"`
	}

	var typ string
	if desc.Private {
		typ = "private"
	} else {
		typ = "public"
	}

	h := sha256.Sum256(body)
	fileHash := h[:]

	k := Key{
		Path:       path,
		Type:       typ,
		Algorithm:  desc.Algorithm,
		Hash:       hex.EncodeToString(desc.Hash),
		FileSha256: hex.EncodeToString(fileHash),
	}

	j, err := json.MarshalIndent(k, "", "    ")
	if err != nil {
		return "", errors.Wrapf(err,
			"internal error: failed to marshal key description")
	}

	return string(j), nil
}

func runKeyShowCmd(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		ImgmodUsage(cmd, nil)
	}

	for i, arg := range args {
		bin, err := ioutil.ReadFile(arg)
		if err != nil {
			ImgmodUsage(nil, err)
		}

		desc, err := ikey.KeyBytesToDesc(bin)
		if err != nil {
			ImgmodUsage(nil, errors.Wrapf(err, "file: \"%s\"", arg))
		}

		j, err := keyDescToJson(arg, bin, desc)
		if err != nil {
			ImgmodUsage(nil, err)
		}

		fmt.Printf("%s", j)
		if i < len(args)-1 {
			fmt.Printf(",")
		}
		fmt.Printf("\n")
	}
}

func AddKeyCommands(cmd *cobra.Command) {
	keyCmd := &cobra.Command{
		Use:   "key",
		Short: "Manipulates image keys",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Usage()
		},
	}
	cmd.AddCommand(keyCmd)

	showCmd := &cobra.Command{
		Use:   "show <key-file> [key-files...]",
		Short: "Displays JSON describing one or more keys",
		Run:   runKeyShowCmd,
	}

	keyCmd.AddCommand(showCmd)
}
