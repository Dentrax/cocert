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
	encryptFile, encryptInput, encryptOutput, encryptKey string
)

var cmdEncrypt = &cobra.Command{
	Use:   "encrypt {-f file | -i STDIN} [-k key] [-o output]",
	Short: "Encrypt the target private keys using TUF",
	Long:  ``,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if encryptFile != "" && encryptInput != "" {
			return fmt.Errorf("--file and --input are mutually exclusive, can not be set at same time")
		}
		if encryptFile == "" && encryptInput == "" {
			return fmt.Errorf("one of the --file or --input are required")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		b, err := signed.DecodePEMFromFile("", readFileOrInput(encryptFile, encryptInput), decidePassFunc(encryptKey), encrypted.Encrypt, true, true)
		not(err)

		err = signed.EncodePEMToFileOrOutput(encryptOutput, b)
		not(err)
	},
}

func init() {
	cmdEncrypt.Flags().StringVarP(&encryptFile, "file", "f", "", "file path to decrypt")
	cmdEncrypt.Flags().StringVarP(&encryptInput, "input", "i", "", "file content to decrypt")
	cmdEncrypt.Flags().StringVarP(&encryptOutput, "output", "o", "", "print PEM content to output file")
	cmdEncrypt.Flags().StringVarP(&encryptKey, "key", "k", "", "decryption key (DO NOT RECOMMENDED - use non-echoed instead)")

	rootCmd.AddCommand(cmdEncrypt)
}
