before fix

$ go run cmd/poc_extract_vulnerable.go malicious.tar.gz
[+] Simulated WorkingDir: /tmp/cx-poc-workdir-26224260
[VULN] os.Create("/tmp/cx_pwn_traversal_test")
[VULN] os.Mkdir("/tmp/cx_pwn_traversal_dir", 0755)
[!! PWNED] /tmp/cx_pwn_traversal_test exists (mode=-rwxrwxrwx size=47)
[!! PWNED] /tmp/cx_pwn_traversal_dir exists (mode=drwxr-xr-x size=4096)

after fic 

$ go run cmd/poc_extract_fixed.go  malicious.tar.gz
[+] Simulated WorkingDir: /tmp/cx-poc-workdir-2513101001
[+] extractFiles stopped (expected for malicious.tar.gz): illegal file path (traversal): ../../../../../../../tmp/cx_pwn_traversal_test
[+] OK: neither /tmp/cx_pwn_traversal_test nor /tmp/cx_pwn_traversal_dir was created outside the workdir by this run.

