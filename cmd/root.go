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
	"io/ioutil"
	"os"

	"github.com/Dentrax/cocert/pkg/password"
	"github.com/Dentrax/cocert/pkg/signed"

	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "cocert",
		Short: "cocert is a sigstore powered certificate generator built-on top of Shamir's Secret Sharing",
	}
)

var (
	readFileOrInput = func(file, input string) []byte {
		if file != "" {
			ff, err := ioutil.ReadFile(file)
			not(err)
			return ff
		}
		return []byte(input)
	}

	decidePassFunc = func(key string) signed.PassFunc {
		if len(key) > 0 {
			return func(confirm bool, message string, enforceTerminal bool) ([]byte, error) {
				return []byte(key), nil
			}
		}
		return password.GetPass
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func not(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
