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

func TestValidateDiscordAllowsDMOnly(t *testing.T) {
	cfg := Default()
	cfg.Discord.AllowedUserIDs = []string{"123"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateDiscordRequiresApproverWhenChannelSet(t *testing.T) {
	cfg := Default()
	cfg.Discord.ChannelID = "456"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected Discord config to require allowed_user_ids")
	}
}
