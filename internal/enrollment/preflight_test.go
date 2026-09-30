package enrollment

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestEvaluateAcceptsCanonicalCurrentClientSurface(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	decision := Evaluate(Request{
		DisplayName: "  Living Room TV  ",
		Platform:    " Google-TV ",
		PublicKey:   "  " + key + "  ",
	})

	if !decision.Eligible {
		t.Fatalf("Evaluate() eligible = false, reason = %s", decision.ReasonCode)
	}
	if decision.ReasonCode != "READY_FOR_AUTHORIZED_ENROLLMENT" {
		t.Fatalf("reason code = %q", decision.ReasonCode)
	}
	if decision.Request == nil {
		t.Fatal("normalized request is nil")
	}
	if decision.Request.DisplayName != "Living Room TV" {
		t.Fatalf("display name = %q", decision.Request.DisplayName)
	}
	if decision.Request.Platform != "google-tv" {
		t.Fatalf("platform = %q", decision.Request.Platform)
	}
	if decision.Request.PublicKey != key {
		t.Fatalf("public key was not canonicalized")
	}
}

func TestEvaluateAcceptsInternationalizedDisplayName(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32))
	decision := Evaluate(Request{
		DisplayName: "مطبخ TV",
		Platform:    "android",
		PublicKey:   key,
	})
	if !decision.Eligible {
		t.Fatalf("internationalized display name rejected: %+v", decision)
	}
}

func TestEvaluateRejectsMissingFields(t *testing.T) {
	decision := Evaluate(Request{})
	if decision.Eligible || decision.ReasonCode != "INVALID_REQUEST" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
}

func TestEvaluateRejectsUnsupportedPlatform(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	decision := Evaluate(Request{DisplayName: "Laptop", Platform: "linux", PublicKey: key})
	if decision.Eligible || decision.ReasonCode != "UNSUPPORTED_PLATFORM" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
}

func TestEvaluateRejectsMalformedOrZeroPublicKey(t *testing.T) {
	for _, key := range []string{
		"not-base64",
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 31)),
		base64.StdEncoding.EncodeToString(make([]byte, 32)),
	} {
		decision := Evaluate(Request{DisplayName: "Phone", Platform: "android", PublicKey: key})
		if decision.Eligible || decision.ReasonCode != "INVALID_PUBLIC_KEY" {
			t.Fatalf("key %q produced unexpected decision: %+v", key, decision)
		}
	}
}

func TestEvaluateRejectsOversizedDisplayName(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x21}, 32))
	decision := Evaluate(Request{
		DisplayName: string(bytes.Repeat([]byte{'a'}, maxDisplayNameBytes+1)),
		Platform:    "ios",
		PublicKey:   key,
	})
	if decision.Eligible || decision.ReasonCode != "INVALID_DISPLAY_NAME" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
}

func TestEvaluateRejectsUnsafeDisplayNameEncoding(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	for _, displayName := range []string{
		"Kitchen\nTV",
		"Kitchen\u202eTV",
		string([]byte{0xff, 'T', 'V'}),
	} {
		decision := Evaluate(Request{
			DisplayName: displayName,
			Platform:    "android",
			PublicKey:   key,
		})
		if decision.Eligible || decision.ReasonCode != "INVALID_DISPLAY_NAME" {
			t.Fatalf("display name %q produced unexpected decision: %+v", displayName, decision)
		}
	}
}
