package crypto

// ZeroBytes overwrites a byte slice with zeros in memory.
//
// In cryptographic applications, sensitive material (like plaintext data keys)
// should not linger in heap memory waiting for garbage collection. While Go's
// runtime manages memory, explicitly wiping the underlying backing array ensures
// that core dumps, heap snapshots, or memory inspects cannot extract stale keys.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
