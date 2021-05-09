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
	splitPrivateKeyFile        string
	splitParts, splitThreshold uint8
)

var cmdSplit = &cobra.Command{
	Use:   "split [-p parts] [-t threshold]",
	Short: "Split your existing private key into parts",
	PreRun: func(cmd *cobra.Command, args []string) {
		if parts < 2 || parts > 255 {
			not(fmt.Errorf("the parts must be at least 2, and less than 256"))
		}
		if threshold < 2 || threshold > 255 {
			not(fmt.Errorf("the threshold must be at least 2, and less than 256"))
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(os.Stdout, "Splitting private key to Shamir PEMs...")
		keys, err := signed.GenerateShamirPEMsToMemAsArrayFromCustomPrivateKey(splitPrivateKeyFile, int(splitParts), int(splitThreshold))
		not(err)

		fmt.Fprintln(os.Stdout, "Extracting PEMs to files...")
		err = signed.ExtractPEMsToCurrentDir(password.GetPass, password.GetPrompterYN, keys)
		not(err)
	},
}

func init() {
	cmdSplit.PersistentFlags().StringVarP(&splitPrivateKeyFile, "file", "f", "", "private key to split")
	cmdSplit.PersistentFlags().Uint8VarP(&splitParts, "parts", "p", 3, "splits a `parts` number of shares")
	cmdSplit.PersistentFlags().Uint8VarP(&splitThreshold, "threshold", "t", 2, "`threshold` count of which are required to reconstruct the secret")
	_ = cmdSplit.MarkPersistentFlagRequired("parts")
	_ = cmdSplit.MarkPersistentFlagRequired("threshold")

	rootCmd.AddCommand(cmdSplit)
}
