package webview2bridge

import "testing"

func TestLanguageModelSliceLengths(t *testing.T) {
	if len(elevenV3Codes) != 74 {
		t.Fatalf("eleven_v3: got %d want 74", len(elevenV3Codes))
	}
	if len(multilingualV2Codes) != 29 {
		t.Fatalf("multilingual v2: got %d want 29", len(multilingualV2Codes))
	}
	if len(flashTurboV25Codes) != 32 {
		t.Fatalf("flash/turbo v2.5: got %d want 32", len(flashTurboV25Codes))
	}
}

func TestValidateLanguageForModel_Vietnamese(t *testing.T) {
	if err := ValidateLanguageForModel("eleven_multilingual_v2", "vi"); err == nil {
		t.Fatal("multilingual v2 must reject vi")
	}
	if err := ValidateLanguageForModel("eleven_turbo_v2_5", "vi"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLanguageForModel("eleven_flash_v2_5", "vi"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLanguageForModel("eleven_v3", "vi"); err != nil {
		t.Fatal(err)
	}
}
