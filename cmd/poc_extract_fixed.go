// Patched extraction logic aligned with ast-cli linux-mac-utils.go (post-fix pattern):
// safeJoin, MkdirAll under working dir only, io.LimitReader, conservative chmod.
// Compare with poc_extract_vulnerable.go using the same malicious.tar.gz.
package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// dirDefault is the permission bits applied to directories created during extraction.
const dirDefault os.FileMode = 0755

// maxExtractBytes caps how many bytes a single tar entry may expand to,
// preventing decompression-bomb (tar-bomb) attacks.
const maxExtractBytes int64 = 500 * 1024 * 1024 // 500 MB

type InstallationConfiguration struct{ workingDir string }

func (c *InstallationConfiguration) WorkingDir() string { return c.workingDir }

func UnzipOrExtractFiles(c *InstallationConfiguration, tarPath string) error {
	gzipStream, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer gzipStream.Close()

	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		return err
	}
	defer uncompressedStream.Close()

	return extractFiles(c, tar.NewReader(uncompressedStream))
}

// safeJoin validates that name is a relative path and that the resolved
// destination stays inside workingDir, preventing path traversal attacks.
func safeJoin(workingDir, name string) (string, error) {
	if name == "" || name == "." {
		return "", fmt.Errorf("illegal file path (empty or dot): %s", name)
	}
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("illegal file path (absolute): %s", name)
	}
	dst := filepath.Join(workingDir, name)
	cleanBase := filepath.Clean(workingDir) + string(os.PathSeparator)
	if !strings.HasPrefix(dst, cleanBase) {
		return "", fmt.Errorf("illegal file path (traversal): %s", name)
	}
	return dst, nil
}

func extractFiles(c *InstallationConfiguration, tarReader *tar.Reader) error {
	workingDir := c.WorkingDir()
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("ExtractTarGz: Next() failed: %w", err)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			dst, err := safeJoin(workingDir, header.Name)
			if err != nil {
				return err
			}
			fmt.Printf("[FIX] os.MkdirAll(%q, 0755)\n", dst)
			if err := os.MkdirAll(dst, dirDefault); err != nil {
				return fmt.Errorf("ExtractTarGz: Mkdir() failed: %w", err)
			}

		case tar.TypeReg:
			extractedFilePath, err := safeJoin(workingDir, header.Name)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(extractedFilePath), dirDefault); err != nil {
				return fmt.Errorf("ExtractTarGz: MkdirAll() failed: %w", err)
			}
			fmt.Printf("[FIX] os.Create(%q)\n", extractedFilePath)
			outFile, err := os.Create(extractedFilePath)
			if err != nil {
				return fmt.Errorf("ExtractTarGz: Create() failed: %w", err)
			}
			if _, err = io.Copy(outFile, io.LimitReader(tarReader, maxExtractBytes)); err != nil {
				_ = outFile.Close()
				return fmt.Errorf("ExtractTarGz: Copy() failed: %w", err)
			}
			if err = outFile.Close(); err != nil {
				return err
			}
			mode := os.FileMode(0644)
			if header.FileInfo().Mode()&0111 != 0 {
				mode = 0755
			}
			if err = os.Chmod(extractedFilePath, mode); err != nil {
				return err
			}

		default:
			log.Printf("ExtractTarGz: unknown type: %v in %s", header.Typeflag, header.Name)
		}
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: poc_extract_fixed <malicious.tar.gz>")
		os.Exit(1)
	}

	tmp, err := os.MkdirTemp("", "cx-poc-workdir-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmp)
	cfg := &InstallationConfiguration{workingDir: tmp}
	fmt.Printf("[+] Simulated WorkingDir: %s\n", tmp)

	if err := UnzipOrExtractFiles(cfg, os.Args[1]); err != nil {
		fmt.Printf("[+] extractFiles stopped (expected for malicious.tar.gz): %v\n", err)
	} else {
		fmt.Println("[+] extractFiles completed without error")
	}

	pwned := false
	for _, p := range []string{"/tmp/cx_pwn_traversal_test", "/tmp/cx_pwn_traversal_dir"} {
		if info, err := os.Stat(p); err == nil {
			fmt.Printf("[!! STILL PWNED] %s exists (mode=%v size=%d)\n", p, info.Mode(), info.Size())
			pwned = true
		}
	}
	if !pwned {
		fmt.Println("[+] OK: neither /tmp/cx_pwn_traversal_test nor /tmp/cx_pwn_traversal_dir was created outside the workdir by this run.")
	}
}
