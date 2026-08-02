package camoufoxbridge

import (
	"fmt"
	"sort"
	"strings"
)

// LanguageOption — 1 mã gửi API (language_code) + nhãn hiển thị.
type LanguageOption struct {
	Code  string `json:"code"`
	Label string `json:"label"`
}

// Nhãn tiếng Anh theo tài liệu ElevenLabs; Code là language_code dùng trong API (vd. vi, zh, fil — không dùng vie, cmn).
// https://help.elevenlabs.io/hc/en-us/articles/13313366263441-What-languages-do-you-support
var languageLabelByCode = map[string]string{
	"af":  "Afrikaans",
	"ar":  "Arabic",
	"hy":  "Armenian",
	"as":  "Assamese",
	"az":  "Azerbaijani",
	"be":  "Belarusian",
	"bn":  "Bengali",
	"bs":  "Bosnian",
	"bg":  "Bulgarian",
	"ca":  "Catalan",
	"ceb": "Cebuano",
	"ny":  "Chichewa",
	"hr":  "Croatian",
	"cs":  "Czech",
	"da":  "Danish",
	"nl":  "Dutch",
	"en":  "English",
	"et":  "Estonian",
	"fil": "Filipino",
	"fi":  "Finnish",
	"fr":  "French",
	"gl":  "Galician",
	"ka":  "Georgian",
	"de":  "German",
	"el":  "Greek",
	"gu":  "Gujarati",
	"ha":  "Hausa",
	"he":  "Hebrew",
	"hi":  "Hindi",
	"hu":  "Hungarian",
	"is":  "Icelandic",
	"id":  "Indonesian",
	"ga":  "Irish",
	"it":  "Italian",
	"ja":  "Japanese",
	"jv":  "Javanese",
	"kn":  "Kannada",
	"kk":  "Kazakh",
	"ky":  "Kirghiz",
	"ko":  "Korean",
	"lv":  "Latvian",
	"ln":  "Lingala",
	"lt":  "Lithuanian",
	"lb":  "Luxembourgish",
	"mk":  "Macedonian",
	"ms":  "Malay",
	"ml":  "Malayalam",
	"zh":  "Mandarin Chinese",
	"mr":  "Marathi",
	"ne":  "Nepali",
	"no":  "Norwegian",
	"ps":  "Pashto",
	"fa":  "Persian",
	"pl":  "Polish",
	"pt":  "Portuguese",
	"pa":  "Punjabi",
	"ro":  "Romanian",
	"ru":  "Russian",
	"sr":  "Serbian",
	"sd":  "Sindhi",
	"sk":  "Slovak",
	"sl":  "Slovenian",
	"so":  "Somali",
	"es":  "Spanish",
	"sw":  "Swahili",
	"sv":  "Swedish",
	"ta":  "Tamil",
	"te":  "Telugu",
	"th":  "Thai",
	"tr":  "Turkish",
	"uk":  "Ukrainian",
	"ur":  "Urdu",
	"vi":  "Vietnamese",
	"cy":  "Welsh",
}

// eleven_v3 — 74 ngôn ngữ (Help Center).
var elevenV3Codes = []string{
	"af", "ar", "hy", "as", "az", "be", "bn", "bs", "bg", "ca",
	"ceb", "ny", "hr", "cs", "da", "nl", "en", "et", "fil", "fi",
	"fr", "gl", "ka", "de", "el", "gu", "ha", "he", "hi", "hu",
	"is", "id", "ga", "it", "ja", "jv", "kn", "kk", "ky", "ko",
	"lv", "ln", "lt", "lb", "mk", "ms", "ml", "zh", "mr", "ne",
	"no", "ps", "fa", "pl", "pt", "pa", "ro", "ru", "sr", "sd",
	"sk", "sl", "so", "es", "sw", "sv", "ta", "te", "th", "tr",
	"uk", "ur", "vi", "cy",
}

// eleven_multilingual_v2 — 29 ngôn ngữ.
var multilingualV2Codes = []string{
	"ar", "bg", "zh", "hr", "cs", "da", "nl", "en", "fil", "fi",
	"fr", "de", "el", "hi", "id", "it", "ja", "ko", "ms", "pl",
	"pt", "ro", "ru", "sk", "es", "sv", "ta", "tr", "uk",
}

// Flash v2.5 / Turbo v2.5 — 32 ngôn ngữ (Flash list; Turbo dùng chung trong Help Center).
var flashTurboV25Codes = []string{
	"ar", "bg", "zh", "hr", "cs", "da", "nl", "en", "fil", "fi",
	"fr", "de", "el", "hu", "hi", "id", "it", "ja", "ko", "ms",
	"no", "pl", "pt", "ro", "ru", "sk", "es", "sv", "ta", "tr",
	"uk", "vi",
}

// SupportedLanguagesForModel trả về các language_code hợp lệ + nhãn, sắp xếp theo Label.
func SupportedLanguagesForModel(modelID string) []LanguageOption {
	codes := codesForModelID(strings.TrimSpace(strings.ToLower(modelID)))
	if len(codes) == 0 {
		codes = elevenV3Codes
	}
	out := make([]LanguageOption, 0, len(codes))
	seen := make(map[string]bool)
	for _, c := range codes {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		lbl := languageLabelByCode[c]
		if lbl == "" {
			lbl = c
		}
		out = append(out, LanguageOption{Code: c, Label: lbl})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Label != out[j].Label {
			return out[i].Label < out[j].Label
		}
		return out[i].Code < out[j].Code
	})
	return out
}

func codesForModelID(modelID string) []string {
	switch modelID {
	case "eleven_v3":
		return elevenV3Codes
	case "eleven_multilingual_v2":
		return multilingualV2Codes
	case "eleven_turbo_v2_5", "eleven_flash_v2_5":
		return flashTurboV25Codes
	default:
		return nil
	}
}

// ValidateLanguageForModel kiểm tra language_code với model (sau khi đã gán mặc định rỗng → en).
func ValidateLanguageForModel(modelID, languageCode string) error {
	lang := strings.TrimSpace(strings.ToLower(languageCode))
	if lang == "" {
		return nil
	}
	mid := strings.TrimSpace(strings.ToLower(modelID))
	codes := codesForModelID(mid)
	if len(codes) == 0 {
		return fmt.Errorf("model không được hỗ trợ: %s", modelID)
	}
	for _, c := range codes {
		if strings.EqualFold(c, lang) {
			return nil
		}
	}
	return fmt.Errorf("language_code %q không được model %q hỗ trợ (xem Help Center ElevenLabs)", lang, modelID)
}
