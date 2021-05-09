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
	"context"
	"fmt"
	"os"

	"github.com/Dentrax/cocert/pkg/signed"

	"github.com/spf13/cobra"
)

var (
	filePubKey          string
	filePubCert         string
	fileVerifyPayload   string
	fileVerifySignature string
	verifyPayload       string
	verifySignature     string
)

var cmdVerify = &cobra.Command{
	Use:   "verify {-c cert | -f file} {-p payload | -t target} {-s signature | -k key}",
	Short: "Verify the given payload on the supplied signature",
	Long:  ``,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if fileVerifyPayload != "" && verifyPayload != "" {
			return fmt.Errorf("--payload and --target are mutually exclusive, can not be set at same time")
		}
		if fileVerifyPayload == "" && verifyPayload == "" {
			return fmt.Errorf("one of the --payload or --target are required")
		}

		if fileVerifySignature != "" && verifySignature != "" {
			return fmt.Errorf("--signature and --key are mutually exclusive, can not be set at same time")
		}
		if fileVerifySignature == "" && verifySignature == "" {
			return fmt.Errorf("one of the --signature or --key are required")
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		v, err := signed.NewVerifier(filePubKey, filePubCert)
		not(err)

		err = signed.VerifyKey(context.TODO(), v, readFileOrInput(fileVerifyPayload, verifyPayload), readFileOrInput(fileVerifySignature, verifySignature))
		not(err)

		fmt.Fprintln(os.Stdout, "Verified.")
	},
}

func init() {
	cmdVerify.Flags().StringVarP(&filePubKey, "file", "f", "", "path to public key file")
	cmdVerify.Flags().StringVarP(&filePubCert, "cert", "c", "", "path to public certificate file")
	cmdVerify.Flags().StringVarP(&fileVerifyPayload, "target", "t", "", "read raw payload from file")
	cmdVerify.Flags().StringVarP(&fileVerifySignature, "signature", "s", "", "read raw base64 encoded signature from file")
	cmdVerify.Flags().StringVarP(&verifyPayload, "payload", "p", "", "raw payload")
	cmdVerify.Flags().StringVarP(&verifySignature, "key", "k", "", "raw base64 encoded signature")
	_ = cmdVerify.MarkFlagRequired("file")

	rootCmd.AddCommand(cmdVerify)
}
