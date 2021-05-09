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
	combineEncryptedFiles   []string
	combineUnEncryptedFiles []string
	combineOutput           string
	combinePEMType          string
)

var cmdCombine = &cobra.Command{
	Use:   "combine {-f file}...",
	Short: "Combine the cert integrity on the supplied PEM files",
	Long: ` 1. Scan every given certs from path
2. Read every file and decode PEM
3. Use Shamir to Combine all private keys
4. Use TUF to decrypt private key
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(os.Stdout, "Loading PEMs from files...")
		s, err := signed.LoadAndCombinePrivateKeysFromPaths(password.GetPass, combineEncryptedFiles, combineUnEncryptedFiles)
		not(err)

		fmt.Fprintln(os.Stdout, "Decrypting TUF encrypted PEMs...")
		_, err = signed.DecryptTUFEncryptedPrivateKey(s, password.GetPass)
		not(err)

		if combineOutput != "" {
			err = signed.EncodePEMToFileOrOutputWithType(combineOutput, s, combinePEMType)
			not(err)
		}

		fmt.Fprintln(os.Stdout, "Combined")
	},
}

func init() {
	cmdCombine.PersistentFlags().StringSliceVarP(&combineEncryptedFiles, "encrypted-file", "f", []string{}, "splitted encrypted file to combine (ask prompt password)")
	cmdCombine.PersistentFlags().StringSliceVarP(&combineUnEncryptedFiles, "unencrypted-file", "F", []string{}, "unecrypted file to combine")
	cmdCombine.PersistentFlags().StringVarP(&combineOutput, "output", "o", "", "print PEM content to output file")
	cmdCombine.PersistentFlags().StringVarP(&combinePEMType, "type", "t", "", "overwrite PEM type header")
	_ = cmdCombine.MarkPersistentFlagRequired("file")

	rootCmd.AddCommand(cmdCombine)
}
