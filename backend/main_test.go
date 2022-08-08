package main

import (
	"math/rand"
	"strings"
	"testing"
	"time"
)

func randomString(n int, alphabet []rune) string {

	alphabetSize := len(alphabet)
	var sb strings.Builder

	for i := 0; i < n; i++ {
		ch := alphabet[rand.Intn(alphabetSize)]
		sb.WriteRune(ch)
	}

	s := sb.String()
	return s
}

func TestAuthenticationValid(t *testing.T) {

}

func TestRedisClient(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	var alphabet []rune = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

	randomStringValue := randomString(20, alphabet)

	err := RedisClient.Set(ctx, "key", randomStringValue, 0).Err()
	if err != nil {
		t.Errorf("Key was not set: %d", err)
		return
	}

	result, err := RedisClient.Get(ctx, "key").Result()
	if err != nil {
		t.Errorf("Key could not be grabbed: %d", err)
		return
	}

	if result != randomStringValue {
		t.Error("Result was not set")
		return
	}
}
