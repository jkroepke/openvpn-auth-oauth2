package crypto

import "testing"

func TestPutScratchClearsEncryptedScratch(t *testing.T) {
	t.Parallel()

	cipher, err := New("test-key")
	if err != nil {
		t.Fatal(err)
	}

	scratch := cipher.getScratch()

	for index := range scratch.encrypted {
		scratch.encrypted[index] = 0xff
	}

	cipher.putScratch(scratch)

	for index, value := range scratch.encrypted {
		if value != 0 {
			t.Fatalf("encrypted scratch byte %d was not cleared", index)
		}
	}
}
