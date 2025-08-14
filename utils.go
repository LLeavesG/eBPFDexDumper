package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"strings"
	"syscall"
)

func ByteToString(bs []int8) string {
	ba := make([]byte, 0, len(bs))
	for _, b := range bs {
		ba = append(ba, byte(b))
	}
	return string(bytes.TrimSpace(bytes.Trim(ba, "\x00")))
}

func CheckConfig(targetStr string) bool {
	file, err := os.Open("/proc/config.gz")
	if err != nil {
		return false
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return false
	}
	defer gzReader.Close()

	scanner := bufio.NewScanner(gzReader)
	target := []byte(targetStr)
	for scanner.Scan() {
		if bytes.Contains(scanner.Bytes(), target) {
			// fmt.Println(scanner.Text())
			return true
		}
	}
	return false
}

func FindBTFAssets() string {
	var utsname syscall.Utsname
	err := syscall.Uname(&utsname)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	btf_file := "a12-5.10-arm64_min.btf"
	if strings.Contains(ByteToString(utsname.Release[:]), "rockchip") {
		btf_file = "rock5b-5.10-arm64_min.btf"
	}
	fmt.Printf("Load btf_file=%s\n", btf_file)
	return btf_file
}
