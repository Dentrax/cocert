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

	"github.com/Dentrax/cocert/pkg/signed"

	"github.com/spf13/cobra"
	"github.com/theupdateframework/go-tuf/encrypted"
)

var (
	decryptFile, decryptInput, decryptOutput, decryptKey string
)

var cmdDecrypt = &cobra.Command{
	Use:   "decrypt {-f file | -i STDIN} [-k key] [-o output]",
	Short: "Decrypt the target private keys using TUF",
	Long:  ``,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if decryptFile != "" && decryptInput != "" {
			return fmt.Errorf("--file and --input are mutually exclusive, can not be set at same time")
		}
		if decryptFile == "" && decryptInput == "" {
			return fmt.Errorf("one of the --file or --input are required")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		b, err := signed.DecodePEMFromFile("", readFileOrInput(decryptFile, decryptInput), decidePassFunc(decryptKey), encrypted.Decrypt, false, false)
		not(err)

		err = signed.EncodePEMToFileOrOutput(decryptOutput, b)
		not(err)
	},
}

func init() {
	cmdDecrypt.Flags().StringVarP(&decryptFile, "file", "f", "", "file path to decrypt")
	cmdDecrypt.Flags().StringVarP(&decryptInput, "input", "i", "", "file content to decrypt")
	cmdDecrypt.Flags().StringVarP(&decryptOutput, "output", "o", "", "print PEM content to output file")
	cmdDecrypt.Flags().StringVarP(&decryptKey, "key", "k", "", "decryption key (DO NOT RECOMMENDED - use non-echoed instead)")

	rootCmd.AddCommand(cmdDecrypt)
}
