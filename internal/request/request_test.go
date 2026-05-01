package request

import "testing"

func TestParseStrictRejectsUnknownFields(t *testing.T) {
	_, err := ParseStrict([]byte(`{
		"schema_version": "1.0",
		"requested_by": "donna",
		"action": "create_visibility_grant",
		"email": "coach@example.com",
		"classification_labels": [],
		"gmail_query": "from:coach@example.com"
	}`))
	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestNormalizeEmailRequiresBareIndividualAddress(t *testing.T) {
	tests := []string{
		"coach@example.com, assistant@example.com",
		"Coach <coach@example.com>",
		"example.com",
		"*@example.com",
	}
	for _, tc := range tests {
		t.Run(tc, func(t *testing.T) {
			if _, err := NormalizeEmail(tc); err == nil {
				t.Fatalf("expected %q to be rejected", tc)
			}
		})
	}

	got, err := NormalizeEmail("Coach@Example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "coach@example.com" {
		t.Fatalf("normalized email = %q", got)
	}
}

func TestParseStrictNormalizesLabels(t *testing.T) {
	req, err := ParseStrict([]byte(`{
		"schema_version": "1.0",
		"requested_by": "donna",
		"action": "create_visibility_grant",
		"email": "coach@example.com",
		"classification_labels": [" Travel ", "Kids/Activities", "travel"]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Kids/Activities", "travel"}
	if len(req.ClassificationLabels) != len(want) {
		t.Fatalf("labels = %#v", req.ClassificationLabels)
	}
	for i := range want {
		if req.ClassificationLabels[i] != want[i] {
			t.Fatalf("labels = %#v, want %#v", req.ClassificationLabels, want)
		}
	}
}
