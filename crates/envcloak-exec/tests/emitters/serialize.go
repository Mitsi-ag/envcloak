// Gate 8's Go serializer (SPEC §15.2): for each variable name given, the
// value in its environment as encoding/json marshals a string, followed by
// a NUL byte. emit.py runs it and replays what it printed.
package main

import (
	"encoding/json"
	"os"
)

func main() {
	for _, name := range os.Args[1:] {
		b, err := json.Marshal(os.Getenv(name))
		if err != nil {
			os.Exit(1)
		}
		os.Stdout.Write(append(b, 0))
	}
}
