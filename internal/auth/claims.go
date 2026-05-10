package auth

// TokenKind discriminates between user access tokens (the default identity
// JWT shape) and RFC 9068 service tokens (typ=at+jwt, carrying a client_id).
type TokenKind int

const (
	// TokenKindUnknown means the parser could not classify the token. Used
	// internally; valid auth outcomes never expose this.
	TokenKindUnknown TokenKind = iota
	// TokenKindUser is an identity user access token.
	TokenKindUser
	// TokenKindService is an RFC 9068 client_credentials access token.
	TokenKindService
)

// String renders the kind for logs and error messages.
func (k TokenKind) String() string {
	switch k {
	case TokenKindUser:
		return "user"
	case TokenKindService:
		return "service"
	default:
		return "unknown"
	}
}

// Claims is the verified, parsed contents of a JWT. Only fields that auth
// decisions depend on are surfaced — the rest of the JWT can stay in the
// parser's hands.
type Claims struct {
	Kind TokenKind

	// Common registered claims.
	Issuer    string
	Subject   string
	Audience  []string
	ExpiresAt int64
	IssuedAt  int64
	JTI       string

	// User-token fields.
	Username string // "usr"
	Role     string // "rol"
	Active   bool   // "act"

	// Service-token fields.
	ClientID string // "client_id"
	Scope    string // "scope"
}

// Principal is the identity that the broker should treat the connection as.
// Returns ok=false for tokens that cannot be associated with any principal —
// which the authenticator should treat as an auth failure.
//
// For user tokens the principal is the username ("usr" claim), falling back
// to the subject ("sub"). For service tokens it is the client_id, falling
// back to the subject. The username-binding check in the authenticator
// compares the MQTT username against this value.
func (c Claims) Principal() (string, bool) {
	switch c.Kind {
	case TokenKindUser:
		if c.Username != "" {
			return c.Username, true
		}
		if c.Subject != "" {
			return c.Subject, true
		}
		return "", false
	case TokenKindService:
		if c.ClientID != "" {
			return c.ClientID, true
		}
		if c.Subject != "" {
			return c.Subject, true
		}
		return "", false
	default:
		return "", false
	}
}
