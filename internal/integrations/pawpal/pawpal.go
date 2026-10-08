package pawpal

import (
	"crypto/subtle"
	"fmt"
	"math"
)

const maxSafeInteger = 9_007_199_254_740_991

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

func VerifyWebhook(providedKey, expectedKey []byte, payload any) WebhookVerification {
	if subtle.ConstantTimeCompare(providedKey, expectedKey) != 1 {
		return WebhookVerification{Outcome: WebhookUnauthorized}
	}

	payloadRecord, ok := payload.(map[string]any)
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed}
	}

	orderID, ok := payloadRecord["orderId"].(float64)
	if !ok || orderID != math.Trunc(orderID) || orderID <= 0 || orderID > maxSafeInteger || payloadRecord["status"] != "approved" {
		return WebhookVerification{Outcome: WebhookMalformed}
	}

	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderID)}
}
