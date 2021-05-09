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
	"io/ioutil"
	"os"

	"github.com/Dentrax/cocert/pkg/signed"

	"github.com/spf13/cobra"
)

var (
	signPrivateKeyFiles []string
	signPrivateKeyFile  string
	signPayload         string
	certOutput          string
	signOutput          string
	signKeyless         bool
)

var cmdSign = &cobra.Command{
	Use:   "sign {-f file}... {-p payload} [-o output]",
	Short: "Sign the given payload and create a certificate from Fulcio",
	Long: `Sign the given payload and create a certificate from Fulcio

EXAMPLES
  # sign a payload using 3 private keys
  cocert sign -f cocert0.key -f cocert1.key -f cocert2.key -p "foo"

  # sign a payload using 2 private keys and create a cert file
  cocert sign -f cocert0.key -f cocert1.key  -p "foo" -o my.cert
`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if len(signPrivateKeyFiles) > 0 && signPrivateKeyFile != "" {
			return fmt.Errorf("--file and --private-key are mutually exclusive, can not be set at same time")
		}
		if len(signPrivateKeyFiles) == 0 && signPrivateKeyFile == "" {
			return fmt.Errorf("one of the --file or --private-key are required")
		}
		if signPrivateKeyFile == "" && len(signPrivateKeyFiles) < 2 {
			return fmt.Errorf("least two --file required to combine splitted Shamir keys")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {

		signer := func() signed.Signer {
			if signKeyless {
				s, err := signed.NewKeylessSigner(context.TODO(), signPrivateKeyFiles, signPrivateKeyFile)
				not(err)
				return s
			}
			s, err := signed.NewKeySigner(context.TODO(), signPrivateKeyFiles, signPrivateKeyFile)
			not(err)
			return s
		}

		encoded, err := signed.CreateSigner(context.TODO(), signer(), []byte(signPayload))
		not(err)

		if certOutput != "" {
			err = ioutil.WriteFile(certOutput, []byte(signer().Cert), 0600)
			not(err)
		}

		if signOutput != "" {
			err = ioutil.WriteFile(signOutput, []byte(encoded), 0600)
			not(err)
		}

		fmt.Fprintln(os.Stdout, "Signed:", encoded)
	},
}

func init() {
	cmdSign.Flags().StringSliceVarP(&signPrivateKeyFiles, "file", "f", []string{}, "splitted private key files (least 2 required)")
	cmdSign.Flags().StringVarP(&signPrivateKeyFile, "private-key", "F", "", "private key file")
	cmdSign.Flags().StringVarP(&signPayload, "payload", "p", "", "raw payload to sign")
	cmdSign.Flags().StringVarP(&certOutput, "output", "o", "", "output file for certificate")
	cmdSign.Flags().StringVarP(&signOutput, "sig-output", "O", "", "output file for signature")
	cmdSign.Flags().BoolVarP(&signKeyless, "keyless", "s", false, "use Fulcio to sign")
	_ = cmdSign.MarkFlagRequired("payload")

	rootCmd.AddCommand(cmdSign)
}
