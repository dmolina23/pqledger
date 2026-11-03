package model

import (
	"encoding/json"
	"testing"
)

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"info": Info, "LOW": Low, " medium ": Medium, "high": High, "Critical": Critical} {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Error("unknown severity should fail")
	}
}

func TestBumpIsCapped(t *testing.T) {
	if Medium.Bump() != High || High.Bump() != Critical || Critical.Bump() != Critical {
		t.Error("Bump should raise one level and stop at Critical")
	}
}

func TestSeverityJSON(t *testing.T) {
	b, err := json.Marshal(High)
	if err != nil || string(b) != `"high"` {
		t.Errorf("got %s, %v", b, err)
	}
}
