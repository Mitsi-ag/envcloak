// Gate 8's Go serializer for the fixture story (emit.py runs it, built by
// the test): for each variable name given, the value in this process's
// environment as encoding/json marshals a string, then NUL, then the
// SHA-256 of the value in hex, then NUL. Nothing else is written, and no
// error holds a value.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
)

func main() {
	for _, name := range os.Args[1:] {
		value, ok := os.LookupEnv(name)
		if !ok {
			os.Stderr.WriteString("emit.go: a variable is not set\n")
			os.Exit(1)
		}
		b, err := json.Marshal(value)
		if err != nil {
			os.Exit(1)
		}
		sum := sha256.Sum256([]byte(value))
		out := append(b, 0)
		out = append(out, []byte(hex.EncodeToString(sum[:]))...)
		out = append(out, 0)
		os.Stdout.Write(out)
	}
}
