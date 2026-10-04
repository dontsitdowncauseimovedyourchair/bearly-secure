package pawpal

import (
	"crypto/subtle"
	"fmt"
	"math"
)

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
)

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(providedKey, expectedKey string, payload any) WebhookVerification {
	if expectedKey == "" || len(providedKey) != len(expectedKey) || subtle.ConstantTimeCompare([]byte(providedKey), []byte(expectedKey)) != 1 {
		return WebhookVerification{Outcome: WebhookUnauthorized}
	}

	payloadRecord, ok := payload.(map[string]any)
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed}
	}

	status, ok := payloadRecord["status"].(string)
	if !ok || status != "approved" {
		return WebhookVerification{Outcome: WebhookMalformed}
	}

	orderID, ok := parseSafeOrderID(payloadRecord["orderId"])
	if !ok || orderID <= 0 {
		return WebhookVerification{Outcome: WebhookMalformed}
	}

	return WebhookVerification{Outcome: WebhookApproved, OrderID: orderID}
}

func parseSafeOrderID(value any) (int64, bool) {
	switch v := value.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Trunc(v) != v || v <= 0 || v > 9_007_199_254_740_991 {
			return 0, false
		}
		return int64(v), true
	case int64:
		if v <= 0 || v > 9_007_199_254_740_991 {
			return 0, false
		}
		return v, true
	case int:
		if v <= 0 {
			return 0, false
		}
		return int64(v), true
	default:
		return 0, false
	}
}
