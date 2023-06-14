package crypto

import (
	"testing"
)

func TestEncryptDES_ECB(t *testing.T) {
	type args struct {
		src string
		key string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Encrypt DES_ECB",
			args: args{
				src: "18060957251",
				key: "20BE865E",
			},
			want: "sAfiBizMy4u9ChCmH9q8Lg==",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EncryptDES_ECB(tt.args.src, tt.args.key); got != tt.want {
				t.Errorf("EncryptDES_ECB() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecryptDES_ECB(t *testing.T) {
	type args struct {
		src string
		key string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Decrypt DES_ECB",
			args: args{
				src: "sAfiBizMy4u9ChCmH9q8Lg==",
				key: "20BE865E",
			},
			want: "18060957251",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DecryptDES_ECB(tt.args.src, tt.args.key); got != tt.want {
				t.Errorf("DecryptDES_ECB() = %v, want %v", got, tt.want)
			}
		})
	}
}
