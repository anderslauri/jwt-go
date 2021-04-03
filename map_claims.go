package jwt

import (
	"encoding/json"
	"errors"
	"time"
)

// Claims type that uses the map[string]interface{} for JSON decoding
// This is the default claims type if you don't supply one.
type MapClaim map[string]interface{}

type MapClaims struct {
	MapClaim
	leeway int64
}

func (m MapClaim) set(k string, v interface{}) MapClaim {
	m[k] = v
	return m
}

func (m MapClaim) get(k string) interface{} {
	return m[k]
}

// Compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyAudience(cmp string, req bool) bool {
	aud, ok := m.get("aud").([]string)
	if !ok {
		strAud, ok := m.get("aud").(string)
		if !ok {
			return false
		}
		aud = append(aud, strAud)
	}
	return verifyAud(aud, cmp, req)
}

// Compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyExpiresAt(cmp int64, req bool) bool {
	switch exp := m.get("exp").(type) {
	case float64:
		return verifyExp(int64(exp), cmp, req)
	case json.Number:
		v, _ := exp.Int64()
		return verifyExp(v, cmp, req)
	}
	return req == false
}

// Compares the iat claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuedAt(cmp int64, req bool) bool {
	switch iat := m.get("iat").(type) {
	case float64:
		return verifyIat(int64(iat)-m.leeway, cmp, req)
	case json.Number:
		v, _ := iat.Int64()
		return verifyIat(v-m.leeway, cmp, req)
	}
	return req == false
}

// Compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuer(cmp string, req bool) bool {
	iss, _ := m.get("iss").(string)
	return verifyIss(iss, cmp, req)
}

// Compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyNotBefore(cmp int64, req bool) bool {
	switch nbf := m.get("nbf").(type) {
	case float64:
		return verifyNbf(int64(nbf)-m.leeway, cmp, req)
	case json.Number:
		v, _ := nbf.Int64()
		return verifyNbf(v-m.leeway, cmp, req)
	}
	return req == false
}

// Leeway sets leeway for validation of claims:
// - Not Before
// - Issued At
// Length of leeway should only be a few minutes.
func (m MapClaims) Leeway(n time.Duration) Claims {
	m.leeway = n.Milliseconds() / 1000
	return m
}

// Validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (m MapClaims) Valid() error {
	vErr := new(ValidationError)
	now := TimeFunc().Unix()

	if m.VerifyExpiresAt(now, false) == false {
		vErr.Inner = errors.New("Token is expired")
		vErr.Errors |= ValidationErrorExpired
	}

	if m.VerifyIssuedAt(now, false) == false {
		vErr.Inner = errors.New("Token used before issued")
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if m.VerifyNotBefore(now, false) == false {
		vErr.Inner = errors.New("Token is not valid yet")
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}
