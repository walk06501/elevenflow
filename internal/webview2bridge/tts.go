package webview2bridge



import (
	"encoding/json"
	"fmt"
	"strings"

	"elevenflow/internal/subtitles"
)



// bridgeMsg là contract JSON giữa JS (chạy trong WV2) và Go.

//   - kind="info"        — tiến độ trung gian (msg)

//   - kind="error"       — lỗi business hoặc HTTP (status + body) hoặc JS exception (error + stack)

//   - kind="audio_done"  — terminal success: data (base64) + bytes (stream/anonymous)

//   - kind="audio_done_ts" — terminal success + alignment (with-timestamps/anonymous)

//   - kind="hcaptcha_blocked" — hCaptcha trả challenge thực tế (Cloudflare flag) → cần đổi proxy

type bridgeMsg struct {

	Kind   string `json:"kind"`

	Msg    string `json:"msg,omitempty"`

	Data   string `json:"data,omitempty"`

	Bytes  int    `json:"bytes,omitempty"`

	Status int    `json:"status,omitempty"`

	Body   string `json:"body,omitempty"`

	Error  string `json:"error,omitempty"`

	Stack  string `json:"stack,omitempty"`

	Alignment *bridgeAlignment `json:"alignment,omitempty"`

}



type bridgeAlignment struct {

	Characters                   []string  `json:"characters"`

	CharacterStartTimesSeconds   []float64 `json:"character_start_times_seconds"`

	CharacterEndTimesSeconds     []float64 `json:"character_end_times_seconds"`

}



func (a *bridgeAlignment) toAlignment() subtitles.Alignment {
	if a == nil {
		return subtitles.Alignment{}
	}
	return subtitles.Alignment{
		Characters: a.Characters,
		Starts:     a.CharacterStartTimesSeconds,
		Ends:       a.CharacterEndTimesSeconds,
	}
}



// IsUnusualActivity nhận diện response "detected_unusual_activity" của ElevenLabs.

func IsUnusualActivity(m bridgeMsg) bool {

	if m.Kind != "error" {

		return false

	}

	if m.Status == 401 {

		return true

	}

	body := strings.ToLower(m.Body)

	return strings.Contains(body, "detected_unusual_activity") ||

		strings.Contains(body, "unusual_activity") ||

		strings.Contains(body, "verify_authenticity")

}



// TTSRequest là input cho 1 chunk TTS.

type TTSRequest struct {

	VoiceID      string

	ModelID      string

	LanguageCode string

	Text         string

	Speed        float64

	Stability       float64

	SimilarityBoost float64

	Style           float64

	UseSpeakerBoost bool

	Sitekey         string

	ExportSRT       bool // true → /stream/with-timestamps/anonymous

}



const modelMultilingualV2 = "eleven_multilingual_v2"

const modelFlashV25 = "eleven_flash_v2_5"

const modelTurboV25 = "eleven_turbo_v2_5"

const modelElevenV3 = "eleven_v3"



func modelUsesFullVoiceSettings(modelID string) bool {

	switch strings.TrimSpace(strings.ToLower(modelID)) {

	case modelMultilingualV2, modelFlashV25, modelTurboV25:

		return true

	default:

		return false

	}

}



func snapStabilityV3(x float64) float64 {

	if x < 0.25 {

		return 0

	}

	if x < 0.75 {

		return 0.5

	}

	return 1

}



func v3SettingsBlockJS(req TTSRequest) string {

	if req.ModelID != modelElevenV3 {

		return ""

	}

	s := snapStabilityV3(req.Stability)

	b, _ := json.Marshal(map[string]float64{"stability": s})

	return "payload.settings = " + string(b) + ";"

}



// ClampTTSSpeed giới hạn tốc độ gửi API anonymous (0.7–1.2). ≤0 → 1.0 mặc định.

func ClampTTSSpeed(speed float64) float64 {

	if speed <= 0 {

		return 1

	}

	if speed < 0.7 {

		return 0.7

	}

	if speed > 1.2 {

		return 1.2

	}

	return speed

}



func voiceSettingsJSON(req TTSRequest) string {

	speed := ClampTTSSpeed(req.Speed)

	if !modelUsesFullVoiceSettings(req.ModelID) {

		b, _ := json.Marshal(map[string]any{"speed": speed})

		return string(b)

	}

	b, _ := json.Marshal(map[string]any{

		"speed":             speed,

		"stability":         req.Stability,

		"use_speaker_boost": req.UseSpeakerBoost,

		"similarity_boost":  req.SimilarityBoost,

		"style":             req.Style,

	})

	return string(b)

}



const ttsScriptCore = `(async () => {

	const send = (kind, extra) => window.chrome.webview.postMessage(JSON.stringify(Object.assign({kind}, extra || {})));

	const exportSRT = __EXPORT_SRT__;

	try {

		send('info', {msg: 'starting'});

		try {

			const ipResp = await fetch('https://api.ipify.org?format=json');

			const ipJson = await ipResp.json();

			send('info', {msg: 'EGRESS-IP=' + ipJson.ip});

		} catch (e) {

			send('info', {msg: 'EGRESS-IP-ERR=' + e.message});

		}

		try {

			var c = document.createElement('canvas');

			var gl = c.getContext('webgl') || c.getContext('experimental-webgl');

			var dbg = gl && gl.getExtension('WEBGL_debug_renderer_info');

			var vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : 'n/a';

			var renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : 'n/a';

			send('info', {msg: 'DIAG:webdriver=' + navigator.webdriver

				+ '|renderer=' + renderer

				+ '|vendor=' + vendor

				+ '|cores=' + navigator.hardwareConcurrency

				+ '|mem=' + (navigator.deviceMemory||'n/a')

				+ '|plugins=' + navigator.plugins.length

				+ '|chromeRT=' + (typeof chrome !== 'undefined' && typeof chrome.runtime !== 'undefined')

				+ '|langs=' + (navigator.languages||[]).join(',')

				+ '|ua=' + navigator.userAgent.substring(0,80)

			});

		} catch(de) { send('info', {msg: 'DIAG-ERR=' + de.message}); }

		if (typeof hcaptcha === 'undefined') {

			send('info', {msg: 'injecting hcaptcha api.js'});

			await new Promise((res, rej) => {

				const s = document.createElement('script');

				s.src = 'https://js.hcaptcha.com/1/api.js?hl=en&render=explicit';

				s.onload = res;

				s.onerror = () => rej(new Error('api.js load failed'));

				document.head.appendChild(s);

			});

			const t0 = Date.now();

			while (typeof hcaptcha === 'undefined') {

				if (Date.now() - t0 > 30000) throw new Error('hcaptcha boot timeout');

				await new Promise(r => setTimeout(r, 100));

			}

		}

		send('info', {msg: 'solving hcaptcha invisible'});

		const old = document.getElementById('_hc_widget');

		if (old) old.remove();

		const el = document.createElement('div');

		el.id = '_hc_widget';

		document.body.appendChild(el);

		const token = await new Promise((resolve, reject) => {

			const timer = setTimeout(() => reject(new Error('hcaptcha 90s timeout')), 90000);

			const wid = hcaptcha.render(el, {

				sitekey: '__SITEKEY__',

				size: 'invisible',

				callback: t => { clearTimeout(timer); resolve(t); },

				'error-callback': e => { clearTimeout(timer); reject(new Error(String(e))); },

				'expired-callback': () => { clearTimeout(timer); reject(new Error('expired')); }

			});

			hcaptcha.execute(wid);

		});

		send('info', {msg: 'token len=' + token.length});



		const voiceSettings = __VOICE_SETTINGS_JSON__;

		const payload = {

			hcaptcha_token: token,

			language_code: '__LANG__',

			model_id: '__MODEL__',

			text: __TEXT_JSON__,

			voice_settings: voiceSettings

		};

		__V3_SETTINGS_BLOCK__



		const ttsURL = exportSRT

			? 'https://api.elevenlabs.io/v1/text-to-speech/__VOICE__/stream/with-timestamps/anonymous?output_format=mp3_44100_128'

			: 'https://api.elevenlabs.io/v1/text-to-speech/__VOICE__/stream/anonymous';

		send('info', {msg: exportSRT ? 'POST tts /with-timestamps/anonymous' : 'POST tts /anonymous'});



		const resp = await fetch(ttsURL, {

			method: 'POST',

			headers: {'Content-Type': 'application/json'},

			body: JSON.stringify(payload)

		});

		if (!resp.ok) {

			const body = await resp.text();

			send('error', {status: resp.status, body: body.substring(0, 4000)});

			return;

		}



		const b64FromBytes = (u8) => {

			let bin = '';

			const CHUNK = 8192;

			for (let i = 0; i < u8.length; i += CHUNK) {

				bin += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));

			}

			return btoa(bin);

		};



		if (!exportSRT) {

			const buf = await resp.arrayBuffer();

			send('info', {msg: 'audio bytes=' + buf.byteLength});

			send('audio_done', {data: b64FromBytes(new Uint8Array(buf)), bytes: buf.byteLength});

			return;

		}



		const appendAlign = (al, chars, starts, ends) => {

			if (!al) return;

			const c = al.characters || [];

			const st = al.character_start_times_seconds || [];

			const en = al.character_end_times_seconds || [];

			for (let i = 0; i < c.length; i++) {

				chars.push(c[i]);

				starts.push(st[i] != null ? st[i] : 0);

				ends.push(en[i] != null ? en[i] : (st[i] != null ? st[i] : 0));

			}

		};

		const parseLine = (line, audioParts, chars, starts, ends) => {

			if (!line) return;

			let obj;

			try { obj = JSON.parse(line); } catch (e) { return; }

			if (obj.audio_base64) {

				const bin = atob(obj.audio_base64);

				const u8 = new Uint8Array(bin.length);

				for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);

				audioParts.push(u8);

			}

			appendAlign(obj.normalized_alignment || obj.alignment, chars, starts, ends);

		};



		if (!resp.body) throw new Error('no response body for timestamps stream');

		const reader = resp.body.getReader();

		const dec = new TextDecoder();

		let buf = '';

		const audioParts = [];

		const chars = [], starts = [], ends = [];

		while (true) {

			const {done, value} = await reader.read();

			if (done) break;

			buf += dec.decode(value, {stream: true});

			let nl;

			while ((nl = buf.indexOf('\n')) >= 0) {

				const line = buf.slice(0, nl).trim();

				buf = buf.slice(nl + 1);

				parseLine(line, audioParts, chars, starts, ends);

			}

		}

		parseLine(buf.trim(), audioParts, chars, starts, ends);



		let total = 0;

		for (const p of audioParts) total += p.length;

		if (total < 2) throw new Error('empty audio from timestamps stream');

		const out = new Uint8Array(total);

		let off = 0;

		for (const p of audioParts) { out.set(p, off); off += p.length; }

		const okMp3 = (out[0] === 0x49 && out[1] === 0x44 && out[2] === 0x33) ||

			(out[0] === 0xFF && (out[1] & 0xE0) === 0xE0);

		if (!okMp3) throw new Error('invalid mp3 after concat');

		if (chars.length === 0) throw new Error('missing alignment');



		send('info', {msg: 'audio bytes=' + out.length + ' align=' + chars.length});

		send('audio_done_ts', {

			data: b64FromBytes(out),

			bytes: out.length,

			alignment: {

				characters: chars,

				character_start_times_seconds: starts,

				character_end_times_seconds: ends

			}

		});

	} catch (e) {

		send('error', {error: String(e && e.message || e), stack: String(e && e.stack || '')});

	}

})();`



// buildTTSScript chèn các tham số runtime vào template.

func buildTTSScript(req TTSRequest) string {

	textJSON, _ := json.Marshal(req.Text)

	sitekey := req.Sitekey

	if sitekey == "" {

		sitekey = "8e58fe8c-1a48-4f94-88ae-8e90b586a192"

	}

	exportSRT := "false"

	if req.ExportSRT {

		exportSRT = "true"

	}

	r := strings.NewReplacer(

		"__SITEKEY__", sitekey,

		"__VOICE__", req.VoiceID,

		"__LANG__", req.LanguageCode,

		"__MODEL__", req.ModelID,

		"__TEXT_JSON__", string(textJSON),

		"__VOICE_SETTINGS_JSON__", voiceSettingsJSON(req),

		"__V3_SETTINGS_BLOCK__", v3SettingsBlockJS(req),

		"__EXPORT_SRT__", exportSRT,

	)

	return r.Replace(ttsScriptCore)

}



// AlignmentFromBridge chuyển bridgeMsg → subtitles.Alignment (gọi từ worker/app).

func AlignmentFromBridge(m bridgeMsg) (subtitles.Alignment, error) {
	if m.Alignment == nil || len(m.Alignment.Characters) == 0 {
		return subtitles.Alignment{}, fmt.Errorf("thiếu alignment trong response TTS")
	}
	return m.Alignment.toAlignment(), nil
}


