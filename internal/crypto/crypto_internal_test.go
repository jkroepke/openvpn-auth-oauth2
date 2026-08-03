package crypto

import "testing"

func TestPutMACClearsEncryptedScratch(t *testing.T) {
	t.Parallel()

	cipher := New("test-key")
	macHash := cipher.getMAC()

	for index := range macHash.encrypted {
		macHash.encrypted[index] = 0xff
	}

	cipher.putMAC(macHash)

	for index, value := range macHash.encrypted {
		if value != 0 {
			t.Fatalf("encrypted scratch byte %d was not cleared", index)
		}
	}
}
