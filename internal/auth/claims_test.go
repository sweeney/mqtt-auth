package auth

import (
	"testing"
)

func TestClaims_Principal(t *testing.T) {
	tests := []struct {
		name    string
		claims  Claims
		want    string
		wantOK  bool
	}{
		{
			name:   "user token returns usr",
			claims: Claims{Kind: TokenKindUser, Subject: "u-123", Username: "alice"},
			want:   "alice",
			wantOK: true,
		},
		{
			name:   "service token returns client_id",
			claims: Claims{Kind: TokenKindService, Subject: "svc-mqtt", ClientID: "svc-mqtt"},
			want:   "svc-mqtt",
			wantOK: true,
		},
		{
			name:   "user token with empty usr falls back to subject",
			claims: Claims{Kind: TokenKindUser, Subject: "u-123"},
			want:   "u-123",
			wantOK: true,
		},
		{
			name:   "service token with empty client_id falls back to subject",
			claims: Claims{Kind: TokenKindService, Subject: "svc-x"},
			want:   "svc-x",
			wantOK: true,
		},
		{
			name:   "unknown kind returns false",
			claims: Claims{Kind: TokenKindUnknown, Subject: "x"},
			wantOK: false,
		},
		{
			name:   "user token with no usr and no subject returns false",
			claims: Claims{Kind: TokenKindUser},
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.claims.Principal()
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("principal = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTokenKind_String(t *testing.T) {
	cases := map[TokenKind]string{
		TokenKindUser:    "user",
		TokenKindService: "service",
		TokenKindUnknown: "unknown",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", k, got, want)
		}
	}
}
