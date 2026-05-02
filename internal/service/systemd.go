package service

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

var systemdTemplate = template.Must(template.New("systemd").Funcs(template.FuncMap{
	"q": systemdQuote,
}).Parse(`[Unit]
Description=Gmail visibility manager ({{ .Instance }})
After=network-online.target

[Service]
Type=simple
ExecStart={{ q .BinaryPath }} --config {{ q .ConfigPath }} run
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes

[Install]
WantedBy=default.target
`))

// SystemdUnit renders a `systemd --user` unit.
func SystemdUnit(spec Spec) (string, error) {
	if err := validateSpec(spec); err != nil {
		return "", err
	}
	var out bytes.Buffer
	if err := systemdTemplate.Execute(&out, spec); err != nil {
		return "", fmt.Errorf("render systemd unit: %w", err)
	}
	return out.String(), nil
}

func systemdQuote(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + replacer.Replace(value) + `"`
}
