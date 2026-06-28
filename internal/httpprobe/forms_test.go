package httpprobe

import "testing"

func TestDetectLoginForm(t *testing.T) {
	if !DetectLoginForm(`<form action="/login"><input type="password" name="password"></form>`) {
		t.Fatal("expected password form to be detected")
	}
	if DetectLoginForm(`<html><body><form><input type="text" name="q"></form></body></html>`) {
		t.Fatal("did not expect generic form to be detected as login")
	}
}
