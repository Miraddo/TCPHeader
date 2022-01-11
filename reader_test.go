package reader_test

import (
	"testing"

	header "github.com/miraddo/TCPHeader"
)

func TestTCPHeader(t *testing.T) {

	var p []header.Packet

	p = []header.Packet{
		{
			Header: []byte{
				0xe5, 0x50,
				0x01, 0xbb,
				0xa5, 0xc6,
				0x16, 0x19,
				0xc7, 0x77,
				0x50, 0x67,
				0x80, 0x10,
				0x0c, 0xb9,
				0xcc, 0xbb,
				0x00, 0x00,
				0x01, 0x01,
				0x08, 0x0a,
				0xd2, 0xbb,
				0x1a, 0x8c,
				0x05, 0xed,
				0xd7, 0x9d,
			},
		},

		{
			Header: []byte{
				0x8a, 0x5c,
				0x01, 0xbb,
				0x4b, 0x28,
				0x9f, 0x37,
				0x7a, 0x82,
				0xc0, 0xd5,
				0x80, 0x10,
				0x01, 0xf5,
				0xde, 0x8e,
				0x00, 0x00,
				0x01, 0x01,
				0x08, 0x0a,
				0xa8, 0x78,
				0xc9, 0x82,
				0x03, 0x46,
				0x75, 0xe5,
			},
		},
	}
	t.Log("Check TCP Source Port Header")
	{
		t.Run("Source Port", func(t *testing.T) {
			// for _, i := range p {

			// 	sp, err := i.SourcePort()

			// 	if err != nil {
			// 		t.Errorf("got an error %v", err)
			// 	}

			// 	if sp != 58704 {
			// 		t.Errorf("expected %d but got %d", 58704, sp)
			// 	}

			// 	do, err := i.SourcePort()

			// 	if err != nil {
			// 		t.Errorf("got an error %v", err)
			// 	}
			// 	fmt.Println(do)
			// }

		})
	}
}
