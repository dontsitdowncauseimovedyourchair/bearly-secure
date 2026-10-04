package pawpal

import (
	"testing"
)

func TestVerifyWebhook(t *testing.T) {
	expectedKey := "secret-api-key"

	// Valid webhook
	v := VerifyWebhook(expectedKey, expectedKey, map[string]any{
		"orderId": float64(42),
		"status":  "approved",
	})
	if v.Outcome != WebhookApproved || v.OrderID != 42 {
		t.Fatalf("expected approved order 42, got %+v", v)
	}

	// Wrong key
	v = VerifyWebhook("wrong-key-length", expectedKey, map[string]any{
		"orderId": float64(42),
		"status":  "approved",
	})
	if v.Outcome != WebhookUnauthorized {
		t.Fatalf("expected unauthorized, got %+v", v)
	}

	// Same length wrong key
	v = VerifyWebhook("secret-api-bad", expectedKey, map[string]any{
		"orderId": float64(42),
		"status":  "approved",
	})
	if v.Outcome != WebhookUnauthorized {
		t.Fatalf("expected unauthorized, got %+v", v)
	}

	// Empty key
	v = VerifyWebhook("", expectedKey, map[string]any{
		"orderId": float64(42),
		"status":  "approved",
	})
	if v.Outcome != WebhookUnauthorized {
		t.Fatalf("expected unauthorized, got %+v", v)
	}

	// Empty expected key
	v = VerifyWebhook("", "", map[string]any{
		"orderId": float64(42),
		"status":  "approved",
	})
	if v.Outcome != WebhookUnauthorized {
		t.Fatalf("expected unauthorized, got %+v", v)
	}

	// Unapproved status
	v = VerifyWebhook(expectedKey, expectedKey, map[string]any{
		"orderId": float64(42),
		"status":  "declined",
	})
	if v.Outcome != WebhookMalformed {
		t.Fatalf("expected malformed for unapproved status, got %+v", v)
	}

	// Missing status
	v = VerifyWebhook(expectedKey, expectedKey, map[string]any{
		"orderId": float64(42),
	})
	if v.Outcome != WebhookMalformed {
		t.Fatalf("expected malformed for missing status, got %+v", v)
	}

	// Missing orderId
	v = VerifyWebhook(expectedKey, expectedKey, map[string]any{
		"status": "approved",
	})
	if v.Outcome != WebhookMalformed {
		t.Fatalf("expected malformed for missing orderId, got %+v", v)
	}

	// Non-positive orderId
	v = VerifyWebhook(expectedKey, expectedKey, map[string]any{
		"orderId": float64(0),
		"status":  "approved",
	})
	if v.Outcome != WebhookMalformed {
		t.Fatalf("expected malformed for zero orderId, got %+v", v)
	}

	v = VerifyWebhook(expectedKey, expectedKey, map[string]any{
		"orderId": float64(-1),
		"status":  "approved",
	})
	if v.Outcome != WebhookMalformed {
		t.Fatalf("expected malformed for negative orderId, got %+v", v)
	}

	// Non-integer orderId
	v = VerifyWebhook(expectedKey, expectedKey, map[string]any{
		"orderId": float64(42.5),
		"status":  "approved",
	})
	if v.Outcome != WebhookMalformed {
		t.Fatalf("expected malformed for non-integer orderId, got %+v", v)
	}

	// Unsafe integer orderId
	v = VerifyWebhook(expectedKey, expectedKey, map[string]any{
		"orderId": float64(10_000_000_000_000_000),
		"status":  "approved",
	})
	if v.Outcome != WebhookMalformed {
		t.Fatalf("expected malformed for unsafe orderId, got %+v", v)
	}

	// Non-map payload
	v = VerifyWebhook(expectedKey, expectedKey, "not a map")
	if v.Outcome != WebhookMalformed {
		t.Fatalf("expected malformed for string payload, got %+v", v)
	}
}
