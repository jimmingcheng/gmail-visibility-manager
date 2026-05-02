package config

import "testing"

func TestDefaultConfigValidForLocalCLI(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateDaemonRequiresClientUID(t *testing.T) {
	cfg := Default()
	if err := cfg.ValidateDaemon(); err == nil {
		t.Fatal("expected daemon config to require client_uid")
	}
	cfg.ClientUID = 501
	if err := cfg.ValidateDaemon(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateGmailRequiresAccountAndOAuthClient(t *testing.T) {
	cfg := Default()
	if err := cfg.ValidateGmail(); err == nil {
		t.Fatal("expected Gmail config requirements")
	}
	cfg.AccountEmail = "you@example.com"
	cfg.OAuthClientPath = "/tmp/oauth-client.json"
	if err := cfg.ValidateGmail(); err != nil {
		t.Fatal(err)
	}
}
