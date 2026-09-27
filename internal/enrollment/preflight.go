package enrollment

import (
	"encoding/base64"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxDisplayNameBytes = 128

var supportedPlatforms = map[string]struct{}{
	"android":   {},
	"google-tv": {},
	"ios":       {},
}

// Request describes the device-owned, non-secret material that can be checked
// before an authenticated enrollment flow is allowed to mutate Network state.
// Identity authorization, device ID assignment, key issuance, and persistence
// are intentionally outside this preflight boundary.
type Request struct {
	DisplayName string `json:"displayName"`
	Platform    string `json:"platform"`
	PublicKey   string `json:"publicKey"`
}

// NormalizedRequest is the canonical request shape returned only after all
// preflight checks pass.
type NormalizedRequest struct {
	DisplayName string `json:"displayName"`
	Platform    string `json:"platform"`
	PublicKey   string `json:"publicKey"`
}

// Decision is deliberately limited to eligibility for a later authenticated
// enrollment transaction. Eligible does not mean enrolled, authorized, or
// connected.
type Decision struct {
	Eligible   bool               `json:"eligible"`
	ReasonCode string             `json:"reasonCode"`
	Reason     string             `json:"reason"`
	Request    *NormalizedRequest `json:"request,omitempty"`
}

// Evaluate performs deterministic, side-effect-free enrollment preflight
// validation. The current Development slice accepts only platforms with native
// repository client surfaces and WireGuard-compatible 32-byte public keys.
func Evaluate(request Request) Decision {
	displayName := strings.TrimSpace(request.DisplayName)
	platform := strings.ToLower(strings.TrimSpace(request.Platform))
	publicKey := strings.TrimSpace(request.PublicKey)

	if displayName == "" || platform == "" || publicKey == "" {
		return deny("INVALID_REQUEST", "displayName, platform, and publicKey are required")
	}
	if !validDisplayName(displayName) {
		return deny("INVALID_DISPLAY_NAME", "displayName contains invalid or unsafe control characters")
	}
	if len([]byte(displayName)) > maxDisplayNameBytes {
		return deny("INVALID_DISPLAY_NAME", "displayName exceeds the Development enrollment limit")
	}
	if _, ok := supportedPlatforms[platform]; !ok {
		return deny("UNSUPPORTED_PLATFORM", "platform does not have an accepted Network enrollment surface")
	}

	decoded, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(decoded) != 32 || allZero(decoded) {
		return deny("INVALID_PUBLIC_KEY", "publicKey must be a non-zero 32-byte base64 public key")
	}

	normalized := &NormalizedRequest{
		DisplayName: displayName,
		Platform:    platform,
		PublicKey:   base64.StdEncoding.EncodeToString(decoded),
	}
	return Decision{
		Eligible:   true,
		ReasonCode: "READY_FOR_AUTHORIZED_ENROLLMENT",
		Reason:     "request is structurally eligible for a later authenticated enrollment transaction",
		Request:    normalized,
	}
}

func deny(code, reason string) Decision {
	return Decision{Eligible: false, ReasonCode: code, Reason: reason}
}

func validDisplayName(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unsafeDisplayFormatRune(r) {
			return false
		}
	}
	return true
}

func unsafeDisplayFormatRune(r rune) bool {
	switch r {
	case '؜', '‎', '‏',
		'‪', '‫', '‬', '‭', '‮',
		'⁦', '⁧', '⁨', '⁩':
		return true
	default:
		return false
	}
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
