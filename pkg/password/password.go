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

package password

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/hashicorp/vault/sdk/helper/password"
	"github.com/mattn/go-isatty"
	"golang.org/x/term"

	"github.com/Songmu/prompter"
)

const CreateNewPasswordMsg string = "Create new password for private key: "
const MasterPasswordMsg string = "Enter your master key: "

func GetPrompterYN(message string, defaultToYes bool) bool {
	return prompter.YN(message, defaultToYes)
}

func GetPass(confirm bool, message string, enforceTerminal bool) ([]byte, error) {
	read := readPasswordFn(enforceTerminal)
	fmt.Fprint(os.Stderr, message)
	pw1, err := read()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if !confirm {
		return pw1, nil
	}
	fmt.Fprint(os.Stderr, "Confirm password: ")
	pw2, err := read()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}

	if string(pw1) != string(pw2) {
		return nil, fmt.Errorf("passwords do not match")
	}
	return pw1, nil
}

func readPasswordFn(enforceTerminal bool) func() ([]byte, error) {
	switch {
	case term.IsTerminal(0) || enforceTerminal:
		isTerminal := isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
		if !isTerminal {
			return func() ([]byte, error) {
				return nil, fmt.Errorf("tty is not a terminal")
			}
		}

		return func() ([]byte, error) {
			value, err := password.Read(os.Stdin)
			if err != nil {
				return nil, err
			}
			return []byte(value), err
		}
	default:
		return func() ([]byte, error) {
			return ioutil.ReadAll(os.Stdin)
		}
	}
}
