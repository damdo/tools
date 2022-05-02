//go:build !linux && !darwin
// +build !linux,!darwin

package main

import "fmt"

func deviceSize(fd uintptr) (uint64, error) {
	return 0, fmt.Errorf("gokrazy is currently missing code for getting device sizes on your operating system. Please see the README at https://github.com/damdo/tools for alternatives, and consider contributing code to fix this")
}

func rereadPartitions(fd uintptr) error {
	return fmt.Errorf("gokrazy is currently missing code for re-reading partition tables on your operating system. Please see the README at https://github.com/damdo/tools for alternatives, and consider contributing code to fix this")
}
