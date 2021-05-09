// Copyright (c) 2021 Furkan Türkal
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package cmd

import (
	"fmt"
	"os"

	"github.com/Dentrax/cocert/pkg/password"
	"github.com/Dentrax/cocert/pkg/signed"

	"github.com/spf13/cobra"
)

var (
	parts, threshold uint8
)

var cmdGenerate = &cobra.Command{
	Use:   "generate [-p parts] [-t threshold]",
	Short: "Generates TUF encrypted keys using ECDSA and splits into PKCS8-PKIX key-pairs",
	Long: `1. Generate ellipticP521 using ECDSA - elliptic.P521.
2. Generate a private key using x509.PKCS8
3. Generate a public key using x509.PKIX
4. Ask for password using 'vault/sdk/helper/password' and encrypt the private key by 'go-tuf/encrypted' algorithm
5. Generate PEM file from public key
6. Split the encrypted private key value using Shamir's Secret Sharing algorithm (vault/shamir)
7. Encode the all returned shares to PEM
8. Extract those to files

* The parts and threshold must be at least 2, and less than 256.
`,
	PreRun: func(cmd *cobra.Command, args []string) {
		if parts < 2 || parts > 255 {
			not(fmt.Errorf("the parts must be at least 2, and less than 256"))
		}
		if threshold < 2 || threshold > 255 {
			not(fmt.Errorf("the threshold must be at least 2, and less than 256"))
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(os.Stdout, "Generating TUF encrypted Shamir PEMs...")
		keys, err := signed.GenerateShamirPEMsToMemAsArray(password.GetPass, int(parts), int(threshold))
		not(err)

		fmt.Fprintln(os.Stdout, "Extracting PEMs to files...")
		err = signed.ExtractPEMsToCurrentDir(password.GetPass, password.GetPrompterYN, keys)
		not(err)
	},
}

func init() {
	cmdGenerate.PersistentFlags().Uint8VarP(&parts, "parts", "p", 3, "generates a `parts` number of shares")
	cmdGenerate.PersistentFlags().Uint8VarP(&threshold, "threshold", "t", 2, "`threshold` count of which are required to reconstruct the secret")
	_ = cmdGenerate.MarkPersistentFlagRequired("parts")
	_ = cmdGenerate.MarkPersistentFlagRequired("threshold")

	rootCmd.AddCommand(cmdGenerate)
}
