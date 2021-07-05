package ed25519

import "testing"

func TestGenerateKeyPemFile(t *testing.T) {
	type args struct {
		privateKeyFile string
		publickKeyFile string
		certPath       string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "test",
			args: args{
				privateKeyFile: "pri.pem",
				publickKeyFile: "pub.pem",
				certPath:       "cert.crt",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := GenerateKeyPemFile(tt.args.privateKeyFile, tt.args.publickKeyFile, tt.args.certPath); (err != nil) != tt.wantErr {
				t.Errorf("GenerateKeyPemFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
