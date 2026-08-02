import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import "./App.css";
import {
  AddSavedVoice,
  CheckServer,
  DefaultOutputDir,
  GenerateBatch,
  GenerateParagraphs,
  GenerateDialogue,
  GetAppConfig,
  SaveOutputDir,
  GetSpeakers,
  SaveSpeakers,
  GetBuildInfo,
  ClearSavedLoginPrefs,
  GetCommercialAuthRequired,
  GetCommercialQuota,
  GetSavedLoginPrefs,
  GetSessionEmail,
  ImportTextFile,
  IsStartupComplete,
  ListSavedVoices,
  Login,
  Logout,
  SaveLoginPrefs,
  OpenFolder,
  PromptOpenOutputFolder,
  RemoveSavedVoice,
  SelectOutputDir,
  SupportedLanguagesForModel,
} from "../wailsjs/go/main/App";
import { EventsOn } from "../wailsjs/runtime/runtime";
import { main, tts } from "../wailsjs/go/models";

/* ── Giọng có sẵn (dropdown) — tùy chỉnh = nhập Voice ID ─── */
const PRESET_VOICES = [
  { label: "Rachel", id: "21m00Tcm4TlvDq8ikWAM", gender: "F" },
  { label: "Domi", id: "AZnzlk1XvdvUeBnXmlld", gender: "F" },
  { label: "Bella", id: "EXAVITQu4vr4xnSDxMaL", gender: "F" },
  { label: "Elli", id: "MF3mGyEYCl7XYWbV9V6O", gender: "F" },
  { label: "Emily", id: "LcfcDJNUP1GQjkzn1xUU", gender: "F" },
  { label: "Grace", id: "oWAxZDx7w5VEj9dCyTzz", gender: "F" },
  { label: "Adam", id: "pNInz6obpgDQGcFmaJgB", gender: "M" },
  { label: "Antoni", id: "ErXwobaYiN019PkySvjV", gender: "M" },
  { label: "Arnold", id: "VR6AewLTigWG4xSOukaG", gender: "M" },
  { label: "Josh", id: "TxGEqnHWrfWFTfGW9XjX", gender: "M" },
  { label: "Sam", id: "yoZ06aMxZJJ28mfd3POQ", gender: "M" },
];

const VOICE_CUSTOM_VALUE = "__custom__";

const DEFAULT_PRESET_ID = PRESET_VOICES[0]?.id ?? "";

const MODEL_ML_V2 = "eleven_multilingual_v2";
const MODEL_FLASH_V25 = "eleven_flash_v2_5";
const MODEL_TURBO_V25 = "eleven_turbo_v2_5";
const MODEL_V3 = "eleven_v3";

/** Cùng nhóm gửi đủ voice_settings (speed, stability, similarity, style, speaker boost) như Multilingual v2. */
function modelUsesFullVoiceSettings(id: string): boolean {
  return id === MODEL_ML_V2 || id === MODEL_FLASH_V25 || id === MODEL_TURBO_V25;
}

const MODELS = [
  { label: "Eleven v3",          id: "eleven_v3",               desc: "Chất lượng cao nhất" },
  { label: "Multilingual v2",    id: "eleven_multilingual_v2",  desc: "Đa ngôn ngữ" },
  { label: "Flash v2.5",         id: "eleven_flash_v2_5",       desc: "Rất nhanh, đa ngôn ngữ" },
  { label: "Turbo v2.5",         id: "eleven_turbo_v2_5",       desc: "Nhanh, đa ngôn ngữ" },
];

/* ── Types ───────────────────────────────────────────────── */
interface ProgressPayload {
  done: number;
  total: number;
  jobId: number;
  /** -1 = merge / hệ thống */
  workerId?: number;
  phase: "rotate" | "captcha" | "tts" | "done" | "error" | "merge";
  message: string;
}
interface Speaker {
  key: number;
  voiceId: string;
  note: string;
}
interface LogEntry {
  id: number;
  time: string;
  phase: ProgressPayload["phase"] | "system";
  text: string;
}
type ServerStatus = "checking" | "online" | "offline";

let _logId = 0;
const mkEntry = (text: string, phase: LogEntry["phase"] = "system"): LogEntry => ({
  id: ++_logId,
  time: new Date().toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
  phase,
  text,
});

/** Ẩn URL, runtime và từ khóa nhà cung cấp trong nhật ký hiển thị cho end-user. */
function sanitizeLogForUser(text: string): string {
  let s = text
    .replace(/https?:\/\/[^\s)\]\}"']+/gi, "")
    .replace(/\bsocks5?:\/\/[^\s)\]\}"']+/gi, "")
    .replace(/\bwebview2\b/gi, "")
    .replace(/microsoft\s+edge\s+runtime/gi, "")
    .replace(/msedgewebview2/gi, "")
    // Không lộ vendor / API ngoài trong log UI
    .replace(/\b1ip\.vn\b/gi, "")
    .replace(/\bapi\.1ip\.vn\b/gi, "")
    .replace(/\b1ip\b/gi, "")
    .replace(/\bchangeip\b/gi, "")
    .replace(/\bsupabase\b/gi, "")
    .replace(/\bvercel\b/gi, "")
    .replace(/session_lease_cap:\d*/gi, "giới hạn kết nối")
    .replace(/rotation_wait:?[^\s]*/gi, "chờ luân chuyển mạng")
    .replace(/\s*[·•]\s*$/g, "")
    .replace(/^\s*[·•]\s*/g, "");
  s = s.replace(/\s{2,}/g, " ").trim();
  return s || "Đã cập nhật.";
}

/** Thông báo lỗi đăng nhập thân thiện — không lộ chi tiết kỹ thuật / API. */
function friendlyLoginError(raw: string): string {
  const low = raw.trim().toLowerCase();
  if (!low) return "Đăng nhập không thành công.";
  if (
    low.includes("invalid_credentials") ||
    low.includes("login_failed") ||
    low.includes("invalid credential") ||
    low.includes("wrong password") ||
    low.includes("email not confirmed")
  ) {
    return "Email hoặc mật khẩu không đúng.";
  }
  if (low.includes("missing_credentials") || low.includes("không được để trống")) {
    return "Vui lòng nhập đủ email và mật khẩu.";
  }
  if (low.includes("unauthorized") || low.includes("401")) {
    return "Phiên không hợp lệ. Thử lại hoặc liên hệ người cấp phép.";
  }
  if (
    low.includes("network") ||
    low.includes("fetch") ||
    low.includes("timeout") ||
    low.includes("failed to fetch") ||
    low.includes("econnrefused") ||
    low.includes("enotfound")
  ) {
    return "Không kết nối được. Kiểm tra Internet và thử lại.";
  }
  if (low.includes("máy chủ không yêu cầu")) {
    return "Phiên bản này không yêu cầu đăng nhập.";
  }
  return "Đăng nhập không thành công. Vui lòng thử lại.";
}

function AuthBrandMark() {
  const gid = useId().replace(/:/g, "");
  return (
    <div className="auth-gate-brand">
      <div className="auth-gate-logo" aria-hidden>
        <svg viewBox="0 0 32 32" width="44" height="44" fill="none">
          <rect width="32" height="32" rx="8" fill={`url(#${gid})`} />
          <path
            d="M9 16c0-3.866 3.134-7 7-7s7 3.134 7 7-3.134 7-7 7-7-3.134-7-7z"
            stroke="white"
            strokeWidth="1.5"
            fill="none"
          />
          <path
            d="M13 16c0-1.657 1.343-3 3-3s3 1.343 3 3-1.343 3-3 3-3-1.343-3-3z"
            fill="white"
            fillOpacity="0.9"
          />
          <path
            d="M16 9v2M16 21v2M9 16H7M25 16h-2"
            stroke="white"
            strokeWidth="1.5"
            strokeLinecap="round"
          />
          <defs>
            <linearGradient id={gid} x1="0" y1="0" x2="32" y2="32">
              <stop offset="0%" stopColor="#3b6ef0" />
              <stop offset="100%" stopColor="#7c3af7" />
            </linearGradient>
          </defs>
        </svg>
      </div>
      <div className="auth-gate-brand-text">
        <span className="auth-gate-product">ElevenFlow</span>
        <span className="auth-gate-tagline">Text to Speech Studio</span>
      </div>
    </div>
  );
}

function batchOutputDirFromResults(results: tts.JobResult[]): string {
  const stripFile = (p: string) => p.replace(/[/\\][^/\\]+$/, "");
  const firstLine = results.find((r) => r.ok && r.output && r.id >= 0);
  if (firstLine?.output) return stripFile(firstLine.output);
  const merged = results.find((r) => r.ok && r.output && r.id < 0);
  if (merged?.output) return stripFile(merged.output);
  return "";
}

/* ── App ─────────────────────────────────────────────────── */
export default function App() {
  const [voiceId, setVoiceId] = useState(DEFAULT_PRESET_ID);
  const [savedVoices, setSavedVoices] = useState<{ voiceId: string; label: string }[]>([]);
  const [modelId, setModelId]         = useState(MODELS[0].id);
  const [speed, setSpeed]             = useState(1.0);
  /** Gửi API khi model = Multilingual v2 / Flash v2.5 / Turbo v2.5 */
  const [stability, setStability] = useState(0.5);
  const [similarityBoost, setSimilarityBoost] = useState(0.75);
  const [styleExaggeration, setStyleExaggeration] = useState(0);
  const [useSpeakerBoost, setUseSpeakerBoost] = useState(true);
  const [lang, setLang]               = useState("vi");

  const [text, setText]       = useState("");
  const [outDir, setOutDir]   = useState("");
  /** Tên gốc file (không .mp3): từng dòng + file ghép; để trống → chunk_xxxx / output.mp3 */
  const [outputFilePrefix, setOutputFilePrefix] = useState("");
  /** Mode 1 khối text: xuất kèm .srt ghép (khớp output.mp3). */
  const [exportSrt, setExportSrt] = useState(false);
  /** Mode đa đoạn: mỗi đoạn → 1 file đánh số (không SRT). */
  const [paragraphMode, setParagraphMode] = useState(false);
  /** Mode hội thoại: nhiều giọng theo marker #N, ghép 1 file. */
  const [dialogueMode, setDialogueMode] = useState(false);
  const [speakers, setSpeakers] = useState<Speaker[]>([]);
  const [speakerModalOpen, setSpeakerModalOpen] = useState(false);
  const [draftSpeakers, setDraftSpeakers] = useState<Speaker[]>([]);

  const [busy, setBusy]                 = useState(false);
  const [log, setLog]                   = useState<LogEntry[]>([]);
  const [progress, setProgress]         = useState({ done: 0, total: 0 });
  const [lastOutput, setLastOutput]     = useState("");
  const [serverStatus, setServerStatus] = useState<ServerStatus>("checking");
  const [bootMsg, setBootMsg]           = useState<string | null>(null);
  const [appVersion, setAppVersion]     = useState("");
  const [commercialRequired, setCommercialRequired] = useState(false);
  const [sessionEmail, setSessionEmail] = useState("");
  const [quotaDisplay, setQuotaDisplay] = useState<{
    text: string;
    title: string;
  } | null>(null);
  const [authChecked, setAuthChecked]   = useState(false);
  const [loginEmailInp, setLoginEmailInp] = useState("");
  const [loginPasswordInp, setLoginPasswordInp] = useState("");
  /** Chỉ lưu email+mật khẩu mã hóa để điền form; không lưu JWT / không bỏ qua bước Đăng nhập. */
  const [rememberForm, setRememberForm] = useState(false);
  const [loginErr, setLoginErr]       = useState("");
  const [loginBusy, setLoginBusy]     = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const langComboRef = useRef<HTMLDivElement>(null);
  const langSearchRef = useRef<HTMLInputElement>(null);

  const [langMenuOpen, setLangMenuOpen] = useState(false);
  const [langSearch, setLangSearch] = useState("");

  useEffect(() => {
    // Ưu tiên thư mục output đã lưu ở lần chạy trước; trống → mặc định cạnh .exe.
    void GetAppConfig()
      .then((cfg) => {
        const saved = (cfg?.outputDir ?? "").trim();
        if (saved) {
          setOutDir(saved);
          return;
        }
        return DefaultOutputDir().then((dir) => setOutDir(dir));
      })
      .catch(() => {
        void DefaultOutputDir().then((dir) => setOutDir(dir)).catch(() => {});
      });
  }, []);

  useEffect(() => {
    void GetSpeakers()
      .then((list) => setSpeakers((list ?? []) as Speaker[]))
      .catch(() => {});
  }, []);

  const filePreview = useMemo(
    () => (outputFilePrefix.trim() ? `${outputFilePrefix.trim()}_001.mp3` : "001.mp3"),
    [outputFilePrefix]
  );

  const openSpeakerModal = useCallback(() => {
    setDraftSpeakers(
      speakers.length
        ? speakers.map((s) => ({ ...s }))
        : [
            { key: 1, voiceId: "", note: "" },
            { key: 2, voiceId: "", note: "" },
          ]
    );
    setSpeakerModalOpen(true);
  }, [speakers]);

  const addDraftSpeaker = useCallback(() => {
    setDraftSpeakers((d) => [
      ...d,
      { key: d.reduce((m, s) => Math.max(m, s.key), 0) + 1, voiceId: "", note: "" },
    ]);
  }, []);

  const updateDraftSpeaker = useCallback(
    (idx: number, field: keyof Speaker, val: string) => {
      setDraftSpeakers((d) =>
        d.map((s, i) =>
          i === idx
            ? { ...s, [field]: field === "key" ? Math.max(1, Number(val) || 1) : val }
            : s
        )
      );
    },
    []
  );

  const removeDraftSpeaker = useCallback((idx: number) => {
    setDraftSpeakers((d) => d.filter((_, i) => i !== idx));
  }, []);

  const saveSpeakers = useCallback(async () => {
    const clean = draftSpeakers
      .filter((s) => s.voiceId.trim())
      .map((s) => ({ key: s.key, voiceId: s.voiceId.trim(), note: s.note.trim() }));
    // Loại trùng key (giữ bản cuối).
    const byKey = new Map<number, Speaker>();
    clean.forEach((s) => byKey.set(s.key, s));
    const finalList = Array.from(byKey.values()).sort((a, b) => a.key - b.key);
    try {
      await SaveSpeakers(finalList);
      setSpeakers(finalList);
      setSpeakerModalOpen(false);
      pushLog(mkEntry(`Đã lưu ${finalList.length} người nói.`, "done"));
    } catch (e: unknown) {
      pushLog(mkEntry(`Lưu người nói lỗi: ${e instanceof Error ? e.message : String(e)}`, "error"));
    }
  }, [draftSpeakers]);

  const lineCount = useMemo(
    () => text.split("\n").filter((l) => l.trim()).length,
    [text]
  );
  const charCount = useMemo(() => text.length, [text]);

  /** Theo ElevenLabs Help Center — chỉ các language_code API chấp nhận cho model. */
  const [langList, setLangList] = useState<{ code: string; label: string }[]>([]);

  useEffect(() => {
    let cancelled = false;
    void SupportedLanguagesForModel(modelId).then((opts) => {
      if (cancelled || !opts?.length) return;
      setLangList(opts.map((o) => ({ code: o.code, label: o.label })));
    });
    return () => {
      cancelled = true;
    };
  }, [modelId]);

  useEffect(() => {
    if (langList.length === 0) return;
    if (!langList.some((x) => x.code === lang)) {
      const en = langList.find((x) => x.code === "en");
      setLang(en?.code ?? langList[0].code);
    }
  }, [langList, lang]);

  const voiceSelectValue = useMemo(() => {
    const m = PRESET_VOICES.find((v) => v.id === voiceId.trim());
    return m ? m.id : VOICE_CUSTOM_VALUE;
  }, [voiceId]);

  const reloadSavedVoices = useCallback(async () => {
    try {
      const list = await ListSavedVoices();
      setSavedVoices(
        list.map((x) => ({ voiceId: x.voiceId, label: x.label }))
      );
    } catch {
      /* bỏ qua — UI vẫn chạy */
    }
  }, []);

  useEffect(() => {
    void reloadSavedVoices();
  }, [reloadSavedVoices]);

  /** Giá trị `<select>` giọng đã lưu: khớp Voice ID hiện tại với danh sách (không phân biệt hoa thường). */
  const savedSelectValue = useMemo(() => {
    const id = voiceId.trim();
    if (!id) return "";
    const hit = savedVoices.find(
      (s) => s.voiceId.toLowerCase() === id.toLowerCase()
    );
    return hit ? hit.voiceId : "";
  }, [voiceId, savedVoices]);

  const v3StabilityLabel = useMemo(() => {
    if (stability === 0) return "0 — Creative";
    if (stability === 0.5) return "0.5 — Cân bằng";
    return "1 — Robust";
  }, [stability]);

  const filteredLangList = useMemo(() => {
    const q = langSearch.trim().toLowerCase();
    if (!q) return langList;
    return langList.filter(
      (x) =>
        x.code.toLowerCase().includes(q) ||
        x.label.toLowerCase().includes(q)
    );
  }, [langList, langSearch]);

  useEffect(() => {
    setLangMenuOpen(false);
    setSpeed((s) => Math.min(1.2, Math.max(0.7, s)));
    if (modelId === MODEL_V3) {
      setStability((s) => {
        const x = Math.min(1, Math.max(0, s));
        if (x <= 0.25) return 0;
        if (x <= 0.75) return 0.5;
        return 1;
      });
    }
  }, [modelId]);

  useEffect(() => {
    if (!langMenuOpen) return;
    const onDoc = (e: MouseEvent) => {
      const el = langComboRef.current;
      if (el && !el.contains(e.target as Node)) setLangMenuOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [langMenuOpen]);

  useEffect(() => {
    if (!langMenuOpen) return;
    const t = window.setTimeout(() => langSearchRef.current?.focus(), 0);
    return () => clearTimeout(t);
  }, [langMenuOpen]);

  useEffect(() => {
    if (!langMenuOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setLangMenuOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [langMenuOpen]);

  const pushLog = useCallback((entry: LogEntry) => {
    setLog((prev) => [...prev.slice(-500), entry]);
  }, []);

  const exportActivityLog = useCallback(() => {
    if (log.length === 0) return;
    const stamp = new Date().toISOString().slice(0, 19).replace(/:/g, "-");
    const header =
      "ElevenFlow — nhật ký hoạt động (UI). Phiên bản hiển thị có thể đã ẩn URL.\n" +
      "Để log đầy đủ từ backend: chạy app với biến môi trường ELEVENFLOW_DIAG_LOG=1 (xem DIAGNOSTICS.md).\n\n";
    const body = log.map((e) => `[${e.time}]\t${e.phase}\t${e.text}`).join("\n");
    const blob = new Blob([header + body], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ElevenFlow-nhat-ky-${stamp}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }, [log]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        for (let i = 0; i < 200 && !cancelled; i++) {
          try {
            if (await IsStartupComplete()) break;
          } catch {
            break;
          }
          await new Promise((r) => setTimeout(r, 50));
        }
        if (cancelled) return;
        const [req, em] = await Promise.all([
          GetCommercialAuthRequired(),
          GetSessionEmail(),
        ]);
        setCommercialRequired(!!req);
        setSessionEmail(typeof em === "string" ? em : "");
      } catch {
        if (!cancelled) {
          setCommercialRequired(false);
          setSessionEmail("");
        }
      } finally {
        if (!cancelled) setAuthChecked(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!authChecked || !commercialRequired || sessionEmail.trim() !== "") return;
    let cancelled = false;
    void (async () => {
      try {
        const p = await GetSavedLoginPrefs();
        if (cancelled || !p?.saved) return;
        setLoginEmailInp(p.email ?? "");
        setLoginPasswordInp(p.password ?? "");
        setRememberForm(true);
      } catch {
        /* bỏ qua */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [authChecked, commercialRequired, sessionEmail]);

  const submitLogin = useCallback(async () => {
    setLoginErr("");
    setLoginBusy(true);
    const em = loginEmailInp.trim();
    const pw = loginPasswordInp;
    try {
      await Login(em, pw);
      if (rememberForm) {
        await SaveLoginPrefs(em, pw);
      } else {
        await ClearSavedLoginPrefs();
      }
      setSessionEmail(await GetSessionEmail());
      setLoginPasswordInp("");
      pushLog(mkEntry("Đã đăng nhập."));
    } catch (e: unknown) {
      setLoginErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoginBusy(false);
    }
  }, [loginEmailInp, loginPasswordInp, rememberForm, pushLog]);

  const doLogout = useCallback(async () => {
    try {
      await Logout();
      setSessionEmail("");
      setQuotaDisplay(null);
      pushLog(mkEntry("Đã đăng xuất."));
    } catch (e: unknown) {
      pushLog(
        mkEntry(
          `Đăng xuất lỗi: ${e instanceof Error ? e.message : String(e)}`,
          "error"
        )
      );
    }
  }, [pushLog]);

  const refreshQuotaDisplay = useCallback(async () => {
    if (!commercialRequired || sessionEmail.trim() === "") {
      setQuotaDisplay(null);
      return;
    }
    try {
      const q = await GetCommercialQuota();
      if (q.unlimited) {
        setQuotaDisplay({
          text: "Không giới hạn",
          title:
            (q.charsUsed ?? 0) > 0
              ? `Đã ghi nhận ${Number(q.charsUsed).toLocaleString("vi-VN")} ký tự đã dùng (hạn max = 0 trên máy chủ)`
              : "Admin chưa đặt hạn mức ký tự (max_chars = 0)",
        });
      } else {
        setQuotaDisplay({
          text: `Còn ${Number(q.remaining).toLocaleString("vi-VN")} ký tự`,
          title: `Đã dùng ${Number(q.charsUsed).toLocaleString("vi-VN")} / tối đa ${Number(q.maxChars).toLocaleString("vi-VN")}`,
        });
      }
    } catch {
      setQuotaDisplay(null);
    }
  }, [commercialRequired, sessionEmail]);

  useEffect(() => {
    if (!authChecked) return;
    void refreshQuotaDisplay();
    const qid = window.setInterval(() => {
      void refreshQuotaDisplay();
    }, 120_000);
    return () => clearInterval(qid);
  }, [authChecked, refreshQuotaDisplay]);

  /* ── events ── */
  useEffect(() => {
    void GetBuildInfo().then((raw) => {
      try {
        const b = main.BuildInfo.createFrom(raw as object);
        if (b.version) setAppVersion(b.version);
      } catch {
        /* ignore */
      }
    });

    const checkServer = () => {
      setServerStatus("checking");
      void CheckServer().then((ok) => setServerStatus(ok ? "online" : "offline"));
    };
    checkServer();
    const interval = setInterval(checkServer, 30_000);

    const offProg = EventsOn("tts:progress", (raw: unknown) => {
      const p = raw as Record<string, unknown>;
      const done =
        typeof p.done === "number"
          ? p.done
          : typeof (p as { Done?: number }).Done === "number"
            ? (p as { Done: number }).Done
            : -1;
      const total =
        typeof p.total === "number"
          ? p.total
          : typeof (p as { Total?: number }).Total === "number"
            ? (p as { Total: number }).Total
            : 0;
      // done < 0 = chỉ log, không ghi đè thanh % (worker đang chạy chunk)
      if (total > 0 && done >= 0) setProgress({ done, total });
      const msg =
        typeof p.message === "string"
          ? p.message
          : typeof (p as { Message?: string }).Message === "string"
            ? (p as { Message: string }).Message
            : "";
      const widRaw = p.workerId ?? (p as { WorkerId?: number }).WorkerId;
      const workerId = typeof widRaw === "number" ? widRaw : -1;
      const ph = (typeof p.phase === "string"
        ? p.phase
        : typeof (p as { Phase?: string }).Phase === "string"
          ? (p as { Phase: string }).Phase
          : "tts") as LogEntry["phase"];
      const safe = sanitizeLogForUser(msg);
      const line =
        workerId >= 0 ? `[Luồng ${workerId}] ${safe}` : safe;
      if (line) pushLog(mkEntry(line, ph));
    });

    const offBoot = EventsOn("bridge:bootstrap", (p: { phase: string; detail: string }) => {
      if (p.phase === "starting" || p.phase === "log") {
        setBootMsg(sanitizeLogForUser(p.detail).slice(0, 200));
      } else {
        setBootMsg(null);
        if (p.detail) pushLog(mkEntry(sanitizeLogForUser(p.detail), "system"));
      }
    });

    return () => {
      clearInterval(interval);
      offProg();
      offBoot();
    };
  }, [pushLog]);

  /* auto-scroll log */
  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: "smooth" });
  }, [log]);

  /* Ctrl+Enter shortcut */
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && !busy && serverStatus === "online") {
        void run();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [busy, serverStatus, voiceId, text, modelId, lang, speed, outDir, outputFilePrefix, stability, similarityBoost, styleExaggeration, useSpeakerBoost]);

  const browse = async () => {
    const dir = await SelectOutputDir();
    if (dir) {
      setOutDir(dir);
      void SaveOutputDir(dir).catch(() => {});
    }
  };

  const importFromFile = useCallback(async () => {
    if (busy) return;
    try {
      const content = await ImportTextFile();
      if (!content) return;
      setText(content);
      pushLog(mkEntry(`Đã nhập ${content.length.toLocaleString()} ký tự từ file.`));
    } catch (e: unknown) {
      pushLog(mkEntry(`Không đọc file: ${e instanceof Error ? e.message : String(e)}`, "error"));
    }
  }, [busy, pushLog]);

  const addCurrentToSaved = useCallback(async () => {
    if (busy) return;
    const id = voiceId.trim();
    if (!id) {
      pushLog(mkEntry("⚠ Nhập Voice ID trước khi lưu.", "error"));
      return;
    }
    const raw = window.prompt("Tên gợi nhớ (tuỳ chọn, để trống = mặc định):") ?? "";
    try {
      await AddSavedVoice(id, raw.trim());
      await reloadSavedVoices();
      pushLog(mkEntry("Đã lưu vào danh sách giọng."));
    } catch (e: unknown) {
      pushLog(
        mkEntry(
          `Không lưu được: ${e instanceof Error ? e.message : String(e)}`,
          "error"
        )
      );
    }
  }, [busy, voiceId, pushLog, reloadSavedVoices]);

  const removeSavedEntry = useCallback(async () => {
    if (busy) return;
    const id = savedSelectValue;
    if (!id) return;
    if (!window.confirm("Xóa giọng này khỏi danh sách đã lưu?")) return;
    try {
      await RemoveSavedVoice(id);
      await reloadSavedVoices();
      pushLog(mkEntry("Đã xóa khỏi danh sách giọng."));
    } catch (e: unknown) {
      pushLog(
        mkEntry(
          `Không xóa được: ${e instanceof Error ? e.message : String(e)}`,
          "error"
        )
      );
    }
  }, [busy, savedSelectValue, pushLog, reloadSavedVoices]);

  const openOutput = () => void OpenFolder(lastOutput || outDir);

  const run = async () => {
    if (dialogueMode) {
      if (!speakers.some((s) => s.voiceId.trim())) {
        pushLog(mkEntry("⚠ Hãy cấu hình ít nhất 1 người nói (Voice ID) cho hội thoại."));
        return;
      }
    } else if (!voiceId.trim()) {
      pushLog(mkEntry("⚠ Voice ID không được để trống."));
      return;
    }
    if (!text.trim())    { pushLog(mkEntry("⚠ Nhập nội dung cần chuyển đổi.")); return; }

    setBusy(true);
    setLangMenuOpen(false);
    setProgress({ done: 0, total: 0 });
    pushLog(
      mkEntry(
        dialogueMode
          ? "Bắt đầu tạo hội thoại nhiều giọng…"
          : paragraphMode
            ? "Bắt đầu xử lý theo đoạn (mỗi đoạn 1 file)…"
            : `Bắt đầu xử lý ${lineCount} dòng…`
      )
    );

    if (outDir.trim()) void SaveOutputDir(outDir.trim()).catch(() => {});

    const params = main.GenerateParams.createFrom({
      voiceId: voiceId.trim(),
      modelId,
      languageCode: lang,
      speed,
      stability,
      similarityBoost,
      style: styleExaggeration,
      useSpeakerBoost,
      text,
      outputDir: outDir,
      outputFilePrefix: outputFilePrefix.trim(),
      maxWorkers: 2,
      exportSrt: paragraphMode || dialogueMode ? false : exportSrt,
      paragraphMode,
      speakers: dialogueMode ? speakers : [],
    });

    try {
      const results = dialogueMode
        ? await GenerateDialogue(params)
        : paragraphMode
          ? await GenerateParagraphs(params)
          : await GenerateBatch(params);
      const ok  = results.filter((r) => r.ok).length;
      const err = results.filter((r) => !r.ok).length;
      results.forEach((r) => {
        if (r.ok && r.output) setLastOutput(r.output.replace(/[^\\/]+$/, "").replace(/[\\/]$/, ""));
        if (r.id === -2) {
          pushLog(
            mkEntry(
              r.ok ? `Phụ đề SRT: ${r.message}` : `Tạo SRT: ${r.message}`,
              r.ok ? "done" : "error"
            )
          );
          return;
        }
        if (r.id < 0) {
          pushLog(
            mkEntry(
              r.ok
                ? `File ghép: ${r.output.split(/[\\/]/).pop() ?? r.output}`
                : `Ghép file: ${r.message}`,
              r.ok ? "done" : "error"
            )
          );
          return;
        }
        const unitLabel = dialogueMode ? "Lượt" : paragraphMode ? "Đoạn" : "Dòng";
        const detail =
          r.ok && r.output ? r.output.split(/[\\/]/).pop() : r.message;
        pushLog(
          mkEntry(`${unitLabel} ${r.id + 1}: ${detail}`, r.ok ? "done" : "error")
        );
      });
      setProgress({ done: ok, total: results.length });
      pushLog(mkEntry(`Hoàn thành — ${ok} thành công${err ? `, ${err} lỗi` : ""}.`));

      const batchDir = batchOutputDirFromResults(results);
      if (batchDir && ok > 0) {
        try {
          const want = await PromptOpenOutputFolder(batchDir);
          if (want) void OpenFolder(batchDir);
        } catch {
          /* bỏ qua lỗi hộp thoại */
        }
      }
    } catch (e: unknown) {
      pushLog(mkEntry(`Lỗi: ${e instanceof Error ? e.message : String(e)}`, "error"));
    } finally {
      setBusy(false);
      void refreshQuotaDisplay();
    }
  };

  const pct = progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0;
  const selectedModel = MODELS.find((m) => m.id === modelId);

  const commercialLoginEl = (
    <div className="auth-gate" role="dialog" aria-modal="true" aria-labelledby="auth-gate-title">
      <div className="auth-gate-ambient" aria-hidden />
      <div className="auth-gate-card">
        <AuthBrandMark />
        <h1 id="auth-gate-title" className="auth-gate-title">
          Đăng nhập
        </h1>
        <p className="auth-gate-lead">
          Nhập email và mật khẩu bạn được cấp để tiếp tục. Mỗi thiết bị chỉ dùng một tài khoản theo quy định của bản cấp phép.
        </p>
        <div className="auth-gate-fields">
          <label className="auth-gate-field">
            <span>Email</span>
            <input
              type="email"
              autoComplete="username"
              value={loginEmailInp}
              onChange={(e) => setLoginEmailInp(e.target.value)}
              disabled={loginBusy}
              className="auth-gate-input"
              placeholder="ten@email.com"
            />
          </label>
          <label className="auth-gate-field">
            <span>Mật khẩu</span>
            <input
              type="password"
              autoComplete="current-password"
              value={loginPasswordInp}
              onChange={(e) => setLoginPasswordInp(e.target.value)}
              disabled={loginBusy}
              className="auth-gate-input"
              placeholder="••••••••"
              onKeyDown={(e) => {
                if (e.key === "Enter") void submitLogin();
              }}
            />
          </label>
        </div>
        <label className="auth-gate-remember">
          <input
            type="checkbox"
            checked={rememberForm}
            onChange={(e) => setRememberForm(e.target.checked)}
            disabled={loginBusy}
          />
          <span>
            Ghi nhớ trên máy này để điền nhanh email và mật khẩu. Mỗi lần mở phần mềm vẫn phải bấm Đăng nhập; không lưu phiên tự động.
          </span>
        </label>
        {loginErr ? (
          <div className="auth-gate-err" role="alert">
            {friendlyLoginError(loginErr)}
          </div>
        ) : null}
        <button
          type="button"
          className="auth-gate-submit"
          disabled={loginBusy || !loginEmailInp.trim() || !loginPasswordInp}
          onClick={() => void submitLogin()}
        >
          {loginBusy ? "Đang xử lý…" : "Đăng nhập"}
        </button>
        <p className="auth-gate-foot">
          Chưa có tài khoản? Liên hệ người đã cấp phép phần mềm cho bạn.
        </p>
      </div>
    </div>
  );

  if (!authChecked) {
    return (
      <div className="auth-gate auth-gate--boot" role="alert" aria-busy="true">
        <div className="auth-gate-ambient" aria-hidden />
        <div className="auth-gate-card auth-gate-card--boot">
          <AuthBrandMark />
          <p className="auth-gate-lead auth-gate-lead--center">Đang khởi động…</p>
          <div className="auth-gate-progress" aria-hidden>
            <div className="auth-gate-progress-bar" />
          </div>
        </div>
      </div>
    );
  }

  if (commercialRequired && sessionEmail.trim() === "") {
    return commercialLoginEl;
  }

  return (
    <div className="app">
      {/* ── Topbar ── */}
      <header className="topbar">
        <div className="topbar-brand">
          <div className="brand-logo">
            <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
              <rect width="32" height="32" rx="8" fill="url(#brandGrad)"/>
              <path d="M9 16c0-3.866 3.134-7 7-7s7 3.134 7 7-3.134 7-7 7-7-3.134-7-7z" stroke="white" strokeWidth="1.5" fill="none"/>
              <path d="M13 16c0-1.657 1.343-3 3-3s3 1.343 3 3-1.343 3-3 3-3-1.343-3-3z" fill="white" fillOpacity="0.9"/>
              <path d="M16 9v2M16 21v2M9 16H7M25 16h-2" stroke="white" strokeWidth="1.5" strokeLinecap="round"/>
              <defs>
                <linearGradient id="brandGrad" x1="0" y1="0" x2="32" y2="32">
                  <stop offset="0%" stopColor="#3b6ef0"/>
                  <stop offset="100%" stopColor="#7c3af7"/>
                </linearGradient>
              </defs>
            </svg>
          </div>
          <div className="brand-text">
            <span className="brand-name">ElevenFlow</span>
            <span className="brand-sub">
              Text to Speech Studio{appVersion ? ` · v${appVersion}` : ""}
            </span>
          </div>
        </div>

        <div className="topbar-right">
          <div className={`status-badge ${serverStatus}`}>
            <span className="status-dot" />
            <span>{serverStatus === "checking" ? "Kết nối…" : serverStatus === "online" ? "Trực tuyến" : "Mất kết nối"}</span>
          </div>
          {commercialRequired && sessionEmail.trim() !== "" && (
            <div className="auth-session">
              <div className="auth-session-text">
                {quotaDisplay && (
                  <span className="auth-quota" title={quotaDisplay.title}>
                    {quotaDisplay.text}
                  </span>
                )}
                <span className="auth-email" title={sessionEmail}>
                  {sessionEmail}
                </span>
              </div>
              <button
                type="button"
                className="btn-auth-out"
                disabled={busy}
                onClick={() => void doLogout()}
              >
                Đăng xuất
              </button>
            </div>
          )}
          <button
            className="btn-run"
            disabled={
              busy ||
              serverStatus !== "online" ||
              (commercialRequired && sessionEmail.trim() === "")
            }
            onClick={() => void run()}
            title="Ctrl+Enter"
          >
            {busy
              ? <><span className="spinner" /> Đang xử lý…</>
              : <><RunIcon /> Tạo Audio</>
            }
          </button>
        </div>
      </header>

      {bootMsg && (
        <div className="boot-bar">
          <span className="boot-dot" />
          <span>{bootMsg}</span>
        </div>
      )}

      <main className="workspace">
        {/* ── Left panel ── */}
        <aside className="panel-left">

          {/* Voice card */}
          <section className="card">
            <div className="card-header">
              <MicIcon />
              <span className="card-title">Giọng đọc</span>
            </div>

            <div className="field voice-row">
              <div className="voice-row-col">
                <label className="field-label" htmlFor="voice-preset-select">Giọng có sẵn</label>
                <select
                  id="voice-preset-select"
                  className="select-input"
                  value={voiceSelectValue}
                  onChange={(e) => {
                    const v = e.target.value;
                    if (v === VOICE_CUSTOM_VALUE) {
                      setVoiceId("");
                      return;
                    }
                    setVoiceId(v);
                  }}
                  disabled={busy}
                >
                  {PRESET_VOICES.map((v) => (
                    <option key={v.id} value={v.id}>
                      {v.label}
                      {v.gender === "F" ? " (nữ)" : v.gender === "M" ? " (nam)" : ""}
                    </option>
                  ))}
                  <option value={VOICE_CUSTOM_VALUE}>Tùy chỉnh — nhập Voice ID</option>
                </select>
              </div>
              <div className="voice-row-col">
                <label className="field-label" htmlFor="voice-id-input">Voice ID</label>
                <input
                  id="voice-id-input"
                  value={voiceId}
                  onChange={(e) => setVoiceId(e.target.value)}
                  placeholder="Dán ID từ ElevenLabs…"
                  spellCheck={false}
                  className="mono-input voice-id-input"
                  disabled={busy}
                />
              </div>
            </div>

            <div className="field voice-saved-row">
              <label className="field-label" htmlFor="voice-saved-select">
                Giọng đã lưu
              </label>
              <select
                id="voice-saved-select"
                className="select-input"
                value={savedSelectValue}
                onChange={(e) => {
                  const v = e.target.value;
                  if (v) setVoiceId(v);
                }}
                disabled={busy}
              >
                <option value="">— Chọn giọng đã lưu —</option>
                {savedVoices.map((s) => (
                  <option key={s.voiceId} value={s.voiceId}>
                    {s.label}
                  </option>
                ))}
              </select>
              <div className="voice-saved-actions">
                <button
                  type="button"
                  className="btn-import"
                  disabled={busy}
                  onClick={() => void addCurrentToSaved()}
                >
                  Lưu ID hiện tại
                </button>
                <button
                  type="button"
                  className="btn-clear"
                  disabled={busy || !savedSelectValue}
                  onClick={() => void removeSavedEntry()}
                >
                  Xóa khỏi danh sách
                </button>
              </div>
            </div>

            <p className="field-hint">
              Chọn giọng có sẵn để điền nhanh. Nhập mã khác với danh sách thì dùng chế độ Tùy chỉnh. Giọng đã lưu được nhớ trên máy này.
            </p>
          </section>

          {/* Model card */}
          <section className="card">
            <div className="card-header">
              <ModelIcon />
              <span className="card-title">Model & Cài đặt</span>
            </div>

            <div className="field">
              <label className="field-label">Model AI</label>
              <select
                className="select-input"
                value={modelId}
                onChange={(e) => setModelId(e.target.value)}
              >
                {MODELS.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.label} — {m.desc}
                  </option>
                ))}
              </select>
            </div>

            <div className="field">
              <label className="field-label">Ngôn ngữ</label>
              <div className="combo" ref={langComboRef}>
                <button
                  type="button"
                  className={`combo-trigger ${langMenuOpen ? "open" : ""}`}
                  disabled={langList.length === 0 || busy}
                  aria-expanded={langMenuOpen}
                  aria-haspopup="listbox"
                  onClick={() => {
                    if (langList.length === 0) return;
                    setLangMenuOpen((o) => !o);
                  }}
                >
                  <span className="combo-value">
                    {langList.length === 0
                      ? "Đang tải…"
                      : langList.find((x) => x.code === lang)?.label ?? lang}
                  </span>
                  <svg className="combo-chevron" width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden>
                    <path d="M4 6l4 4 4-4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </button>
                {langMenuOpen && langList.length > 0 && (
                  <div className="combo-panel" role="listbox">
                    <input
                      ref={langSearchRef}
                      type="search"
                      className="combo-search"
                      placeholder="Tìm theo tên hoặc mã…"
                      value={langSearch}
                      onChange={(e) => setLangSearch(e.target.value)}
                      onMouseDown={(e) => e.stopPropagation()}
                      autoComplete="off"
                      spellCheck={false}
                      aria-label="Tìm ngôn ngữ"
                    />
                    {filteredLangList.length === 0 ? (
                      <div className="combo-empty">Không có ngôn ngữ khớp.</div>
                    ) : (
                      filteredLangList.map((l) => (
                        <button
                          key={l.code}
                          type="button"
                          role="option"
                          aria-selected={l.code === lang}
                          className={`combo-option ${l.code === lang ? "active" : ""}`}
                          onClick={() => {
                            setLang(l.code);
                            setLangSearch("");
                            setLangMenuOpen(false);
                          }}
                        >
                          <span className="combo-option-label">{l.label}</span>
                          <span className="combo-option-code">{l.code}</span>
                        </button>
                      ))
                    )}
                  </div>
                )}
              </div>
              <p className="field-hint">
                Theo Help Center ElevenLabs — chỉ các <code>language_code</code> API hỗ trợ cho model đã chọn (vd. Vietnamese → <code>vi</code>, Mandarin → <code>zh</code>).
              </p>
            </div>

            {modelUsesFullVoiceSettings(modelId) ? (
              <div className="field ml-v2-voice">
                <div className="ml-v2-voice-title">Tinh chỉnh giọng</div>
                <p className="field-hint" style={{ marginTop: 0 }}>
                  Áp dụng Multilingual v2, Flash v2.5 và Turbo v2.5 — gửi kèm <code>voice_settings</code> như bảng ElevenLabs.
                </p>
                <div className="ml-v2-grid">
                  <div className="ml-v2-cell">
                    <label className="field-label">
                      Tốc độ đọc
                      <span className="field-value">{speed.toFixed(2)}×</span>
                    </label>
                    <input
                      type="range" min={0.7} max={1.2} step={0.01}
                      value={speed}
                      onChange={(e) => setSpeed(Number(e.target.value))}
                      className="slider"
                      disabled={busy}
                    />
                    <div className="slider-labels"><span>0.7×</span><span>1×</span><span>1.2×</span></div>
                  </div>
                  <div className="ml-v2-cell">
                    <label className="field-label">
                      Độ ổn định (stability)
                      <span className="field-value">{stability.toFixed(2)}</span>
                    </label>
                    <input
                      type="range" min={0} max={1} step={0.01}
                      value={stability}
                      onChange={(e) => setStability(Number(e.target.value))}
                      className="slider"
                      disabled={busy}
                    />
                    <div className="slider-labels"><span>Biến thiên</span><span></span><span>Ổn định</span></div>
                  </div>
                  <div className="ml-v2-cell">
                    <label className="field-label">
                      Độ tương đồng (similarity)
                      <span className="field-value">{similarityBoost.toFixed(2)}</span>
                    </label>
                    <input
                      type="range" min={0} max={1} step={0.01}
                      value={similarityBoost}
                      onChange={(e) => setSimilarityBoost(Number(e.target.value))}
                      className="slider"
                      disabled={busy}
                    />
                    <div className="slider-labels"><span>Thấp</span><span></span><span>Cao</span></div>
                  </div>
                  <div className="ml-v2-cell">
                    <label className="field-label">
                      Nhấn style (style)
                      <span className="field-value">{styleExaggeration.toFixed(2)}</span>
                    </label>
                    <input
                      type="range" min={0} max={1} step={0.01}
                      value={styleExaggeration}
                      onChange={(e) => setStyleExaggeration(Number(e.target.value))}
                      className="slider"
                      disabled={busy}
                    />
                    <div className="slider-labels"><span>Không</span><span></span><span>Nhấn mạnh</span></div>
                  </div>
                  <div className="ml-v2-cell ml-v2-cell-boost">
                    <label className="checkbox-row">
                      <input
                        type="checkbox"
                        checked={useSpeakerBoost}
                        onChange={(e) => setUseSpeakerBoost(e.target.checked)}
                        disabled={busy}
                      />
                      <span>Speaker boost</span>
                    </label>
                  </div>
                </div>
              </div>
            ) : modelId === MODEL_V3 ? (
              <div className="field v3-voice">
                <div className="v3-voice-title">Tinh chỉnh (Eleven v3)</div>
                <p className="field-hint" style={{ marginTop: 0 }}>
                  Stability chỉ 3 mức — gửi <code>settings.stability</code> trong request (0 / 0.5 / 1).
                </p>
                <div className="v3-stability-block">
                  <label className="field-label">
                    <span className="v3-stability-title">Stability</span>
                    <span className="field-value">{v3StabilityLabel}</span>
                  </label>
                  <input
                    type="range"
                    min={0}
                    max={1}
                    step={0.5}
                    value={stability}
                    onChange={(e) => setStability(Number(e.target.value))}
                    className="slider v3-stability-slider"
                    disabled={busy}
                  />
                  <div className="slider-labels v3-stability-ends">
                    <span>Creative</span>
                    <span className="v3-stability-mid">Cân bằng</span>
                    <span>Robust</span>
                  </div>
                </div>
                <div className="field" style={{ marginTop: 14 }}>
                  <label className="field-label">
                    Tốc độ đọc
                    <span className="field-value">{speed.toFixed(2)}×</span>
                  </label>
                  <input
                    type="range" min={0.7} max={1.2} step={0.01}
                    value={speed}
                    onChange={(e) => setSpeed(Number(e.target.value))}
                    className="slider"
                    disabled={busy}
                  />
                  <div className="slider-labels"><span>0.7×</span><span>1×</span><span>1.2×</span></div>
                </div>
              </div>
            ) : (
              <div className="field">
                <label className="field-label">
                  Tốc độ đọc
                  <span className="field-value">{speed.toFixed(2)}×</span>
                </label>
                <input
                  type="range" min={0.7} max={1.2} step={0.01}
                  value={speed}
                  onChange={(e) => setSpeed(Number(e.target.value))}
                  className="slider"
                  disabled={busy}
                />
                <div className="slider-labels"><span>0.7×</span><span>1×</span><span>1.2×</span></div>
              </div>
            )}
          </section>

          {/* Output card */}
          <section className="card">
            <div className="card-header">
              <FolderIcon />
              <span className="card-title">Lưu file</span>
            </div>

            <div className="field">
              <label className="field-label">Tên file đầu ra (không cần .mp3)</label>
              <input
                value={outputFilePrefix}
                onChange={(e) => setOutputFilePrefix(e.target.value)}
                placeholder="vd: podcast, audiobook_ch01"
                spellCheck={false}
                disabled={busy}
              />
            </div>

            <div className="field">
              <label className="field-label">Chế độ tạo</label>
              <div className="mode-select">
                <button
                  type="button"
                  className={`mode-opt ${!paragraphMode && !dialogueMode ? "active" : ""}`}
                  onClick={() => { setParagraphMode(false); setDialogueMode(false); }}
                  disabled={busy}
                >
                  <span className="mode-opt-icon"><ModeSingleIcon /></span>
                  <span className="mode-opt-text">
                    <span className="mode-opt-title">Một file</span>
                    <span className="mode-opt-desc">Ghép toàn bộ nội dung thành 1 MP3</span>
                  </span>
                  <span className="mode-opt-check"><CheckIcon /></span>
                </button>
                <button
                  type="button"
                  className={`mode-opt ${paragraphMode ? "active" : ""}`}
                  onClick={() => { setParagraphMode(true); setDialogueMode(false); setExportSrt(false); }}
                  disabled={busy}
                >
                  <span className="mode-opt-icon"><ModeParagraphIcon /></span>
                  <span className="mode-opt-text">
                    <span className="mode-opt-title">Theo đoạn</span>
                    <span className="mode-opt-desc">Mỗi đoạn → 1 file ({filePreview})</span>
                  </span>
                  <span className="mode-opt-check"><CheckIcon /></span>
                </button>
                <button
                  type="button"
                  className={`mode-opt ${dialogueMode ? "active" : ""}`}
                  onClick={() => { setDialogueMode(true); setParagraphMode(false); setExportSrt(false); }}
                  disabled={busy}
                >
                  <span className="mode-opt-icon"><ModeDialogueIcon /></span>
                  <span className="mode-opt-text">
                    <span className="mode-opt-title">Hội thoại</span>
                    <span className="mode-opt-desc">Nhiều giọng #1, #2… ghép 1 file</span>
                  </span>
                  <span className="mode-opt-check"><CheckIcon /></span>
                </button>
              </div>

              {dialogueMode && (
                <button
                  type="button"
                  className="speaker-config-btn"
                  onClick={openSpeakerModal}
                  disabled={busy}
                >
                  <SpeakerIcon /> Cấu hình người nói
                  <span className="count-badge">{speakers.length}</span>
                </button>
              )}

              {!paragraphMode && !dialogueMode && (
                <label className="srt-toggle">
                  <input
                    type="checkbox"
                    checked={exportSrt}
                    onChange={(e) => setExportSrt(e.target.checked)}
                    disabled={busy}
                  />
                  <span>Xuất phụ đề SRT (khớp MP3)</span>
                </label>
              )}
            </div>

            <div className="field">
              <label className="field-label">Thư mục xuất</label>
              <div className="dir-row">
                <input
                  value={outDir}
                  onChange={(e) => setOutDir(e.target.value)}
                  placeholder="Mặc định: output cạnh file .exe"
                  spellCheck={false}
                />
                <button className="btn-icon" title="Chọn thư mục" onClick={() => void browse()}>
                  <svg viewBox="0 0 16 16" fill="none"><path d="M2 4.5A1.5 1.5 0 013.5 3h3l1.5 2H12.5A1.5 1.5 0 0114 6.5v5A1.5 1.5 0 0112.5 13h-9A1.5 1.5 0 012 11.5v-7z" stroke="currentColor" strokeWidth="1.2"/></svg>
                </button>
                {(lastOutput || outDir) && (
                  <button className="btn-icon" title="Mở thư mục" onClick={openOutput}>
                    <svg viewBox="0 0 16 16" fill="none"><path d="M6 3H3.5A1.5 1.5 0 002 4.5v7A1.5 1.5 0 003.5 13h9A1.5 1.5 0 0014 11.5V9M10 2h4m0 0v4m0-4L8 8" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  </button>
                )}
              </div>
            </div>
          </section>
        </aside>

        {/* ── Main panel ── */}
        <div className="panel-main">

          {/* Script editor */}
          <section className="card script-card">
            <div className="script-header">
              <div className="card-header" style={{ marginBottom: 0 }}>
                <DocIcon />
                <span className="card-title">Nội dung</span>
              </div>
              <div className="script-meta">
                {charCount > 0 && (
                  <span className="badge-count">
                    {charCount.toLocaleString()} ký tự
                  </span>
                )}
                {selectedModel && (
                  <span className="badge-model">{selectedModel.label}</span>
                )}
              </div>
            </div>
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={
                dialogueMode
                  ? "Tạo hội thoại: mỗi lượt bắt đầu bằng #số người nói.\n\nVí dụ:\n#1 Xin chào, bạn khỏe không?\n#2 Mình khỏe, cảm ơn bạn!\n#1 Hôm nay đi đâu chơi nhé."
                  : paragraphMode
                    ? "Gen theo đoạn: mỗi đoạn → 1 file riêng (001.mp3, 002.mp3…).\nNgăn cách các đoạn bằng 1 dòng trống.\n\nVí dụ:\nĐoạn một. Có thể nhiều câu, nhiều dòng.\n\nĐoạn hai ở đây.\n\nĐoạn ba ở đây."
                    : "Gõ trực tiếp hoặc Mở file… (txt, md, srt).\nToàn bộ nội dung ghép thành 1 file MP3.\n\nVí dụ:\nXin chào, đây là nội dung cần đọc."
              }
              disabled={busy}
              spellCheck={false}
            />
            <div className="script-footer">
              <button
                type="button"
                className="btn-import"
                onClick={() => void importFromFile()}
                disabled={busy}
              >
                Mở file…
              </button>
              <span className="hint">Ctrl+Enter để tạo audio</span>
            </div>
          </section>

          {/* Progress bar (only when running) */}
          {progress.total > 0 && (
            <div className="progress-card">
              <div className="progress-info">
                <span className="progress-label">
                  {busy ? "Đang xử lý…" : "Hoàn thành"}
                </span>
                <span className="progress-count">{progress.done}/{progress.total} ({pct}%)</span>
              </div>
              <div className="progress-track">
                <div
                  className={`progress-fill ${busy ? "animate" : "complete"}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
          )}

          {/* Log */}
          <section className="card log-card">
            <div className="log-header">
              <div className="card-header" style={{ marginBottom: 0 }}>
                <LogIcon />
                <span className="card-title">Nhật ký hoạt động</span>
              </div>
              {log.length > 0 && (
                <div className="log-actions">
                  <button type="button" className="btn-clear" onClick={exportActivityLog}>
                    Xuất nhật ký…
                  </button>
                  <button type="button" className="btn-clear" onClick={() => setLog([])}>Xóa</button>
                </div>
              )}
            </div>
            <div className="log-body" ref={logRef}>
              {log.length === 0 ? (
                <div className="log-empty">
                  <EmptyLogIcon />
                  <p>Nhật ký sẽ hiển thị khi bạn tạo audio</p>
                </div>
              ) : (
                log.map((e) => (
                  <div key={e.id} className={`log-entry phase-${e.phase}`}>
                    <span className="log-time">{e.time}</span>
                    <span className="log-icon">{phaseIcon(e.phase)}</span>
                    <span className="log-text">{e.text}</span>
                  </div>
                ))
              )}
            </div>
          </section>
        </div>
      </main>

      {speakerModalOpen && (
        <div className="auth-gate" role="dialog" aria-modal="true" onClick={() => setSpeakerModalOpen(false)}>
          <div className="auth-gate-card speaker-modal" onClick={(e) => e.stopPropagation()}>
            <div className="speaker-modal-inner">
              <div className="speaker-modal-head">
                <span className="speaker-modal-icon"><SpeakerIcon size={20} /></span>
                <div>
                  <h3 className="speaker-modal-title">Cấu hình người nói</h3>
                  <p className="speaker-modal-sub">
                    Dòng bắt đầu bằng <code>#1</code> đọc bằng giọng #1, <code>#2</code> bằng giọng #2… Cài đặt được lưu cho lần sau.
                  </p>
                </div>
              </div>

              {draftSpeakers.length > 0 && (
                <div className="speaker-list-head" style={{ marginTop: 18 }}>
                  <span>Số</span>
                  <span>Voice ID</span>
                  <span>Ghi chú</span>
                  <span />
                </div>
              )}

              <div className="speaker-list">
                {draftSpeakers.map((s, idx) => (
                  <div key={idx} className="speaker-item">
                    <div className="speaker-key-wrap">
                      <span className="speaker-key-hash">#</span>
                      <input
                        type="number"
                        min={1}
                        value={s.key}
                        onChange={(e) => updateDraftSpeaker(idx, "key", e.target.value)}
                      />
                    </div>
                    <input
                      value={s.voiceId}
                      onChange={(e) => updateDraftSpeaker(idx, "voiceId", e.target.value)}
                      placeholder="Dán Voice ID…"
                      spellCheck={false}
                    />
                    <input
                      value={s.note}
                      onChange={(e) => updateDraftSpeaker(idx, "note", e.target.value)}
                      placeholder="vd: Nam trầm"
                      spellCheck={false}
                    />
                    <button
                      type="button"
                      className="speaker-del"
                      title="Xóa người nói này"
                      onClick={() => removeDraftSpeaker(idx)}
                    >
                      <TrashIcon />
                    </button>
                  </div>
                ))}
                {draftSpeakers.length === 0 && (
                  <div className="speaker-empty">Chưa có người nói nào — bấm “Thêm người nói” để bắt đầu.</div>
                )}
              </div>

              <button type="button" className="speaker-add" onClick={addDraftSpeaker}>
                <PlusIcon /> Thêm người nói
              </button>

              <div className="speaker-modal-foot">
                <button type="button" className="btn-modal-ghost" onClick={() => setSpeakerModalOpen(false)}>
                  Hủy
                </button>
                <button type="button" className="btn-modal-primary" onClick={() => void saveSpeakers()}>
                  Lưu cấu hình
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Phase helpers ────────────────────────────────────────── */
function phaseIcon(phase: LogEntry["phase"]): string {
  switch (phase) {
    case "rotate":  return "↺";
    case "captcha": return "◈";
    case "tts":     return "♪";
    case "merge":   return "🔗";
    case "error":   return "✗";
    default:        return "·";
  }
}

/* ── Icons ───────────────────────────────────────────────── */
function ModeSingleIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <rect x="3" y="2" width="10" height="12" rx="1.5" stroke="currentColor" strokeWidth="1.3" />
      <path d="M5.5 6h5M5.5 8.5h5M5.5 11h3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
    </svg>
  );
}
function ModeParagraphIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <rect x="2.5" y="2.5" width="11" height="3.5" rx="1" stroke="currentColor" strokeWidth="1.3" />
      <rect x="2.5" y="10" width="11" height="3.5" rx="1" stroke="currentColor" strokeWidth="1.3" />
    </svg>
  );
}
function ModeDialogueIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <path d="M2 4.5A1.5 1.5 0 013.5 3h6A1.5 1.5 0 0111 4.5v3A1.5 1.5 0 019.5 9H6l-2.5 2V9h0A1.5 1.5 0 012 7.5v-3z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
      <path d="M11.5 6h1A1.5 1.5 0 0114 7.5v3A1.5 1.5 0 0112.5 12v1.5L11 12" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
    </svg>
  );
}
function CheckIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none">
      <path d="M3.5 8.5l3 3 6-7" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
function SpeakerIcon({ size = 15 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none">
      <path d="M8.5 2.5L4.5 5.5H2v5h2.5l4 3v-11z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round" />
      <path d="M11 5.5a3.5 3.5 0 010 5M12.8 3.5a6 6 0 010 9" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
    </svg>
  );
}
function TrashIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
      <path d="M3 4.5h10M6.5 4V3a1 1 0 011-1h1a1 1 0 011 1v1M5 4.5l.5 8a1 1 0 001 1h3a1 1 0 001-1l.5-8" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
function PlusIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
      <path d="M8 3.5v9M3.5 8h9" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}
function RunIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
      <path d="M4 3l10 5-10 5V3z" fill="currentColor"/>
    </svg>
  );
}
function MicIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none">
      <rect x="5" y="1" width="6" height="9" rx="3" stroke="currentColor" strokeWidth="1.3"/>
      <path d="M3 8a5 5 0 0010 0M8 13v2" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
    </svg>
  );
}
function ModelIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none">
      <rect x="2" y="2" width="5" height="5" rx="1.5" stroke="currentColor" strokeWidth="1.3"/>
      <rect x="9" y="2" width="5" height="5" rx="1.5" stroke="currentColor" strokeWidth="1.3"/>
      <rect x="2" y="9" width="5" height="5" rx="1.5" stroke="currentColor" strokeWidth="1.3"/>
      <rect x="9" y="9" width="5" height="5" rx="1.5" stroke="currentColor" strokeWidth="1.3"/>
    </svg>
  );
}
function FolderIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none">
      <path d="M2 4.5A1.5 1.5 0 013.5 3h3l1.5 2H12.5A1.5 1.5 0 0114 6.5v5A1.5 1.5 0 0112.5 13h-9A1.5 1.5 0 012 11.5v-7z" stroke="currentColor" strokeWidth="1.3"/>
    </svg>
  );
}
function DocIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none">
      <path d="M4 2h6l3 3v9a1 1 0 01-1 1H4a1 1 0 01-1-1V3a1 1 0 011-1z" stroke="currentColor" strokeWidth="1.3"/>
      <path d="M10 2v3h3M6 8h4M6 11h3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
    </svg>
  );
}
function LogIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" fill="none">
      <rect x="2" y="2" width="12" height="12" rx="2" stroke="currentColor" strokeWidth="1.3"/>
      <path d="M5 6h6M5 9h4M5 12h5" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
    </svg>
  );
}
function EmptyLogIcon() {
  return (
    <svg width="36" height="36" viewBox="0 0 36 36" fill="none">
      <circle cx="18" cy="18" r="16" stroke="#1e2540" strokeWidth="2"/>
      <path d="M12 14h12M12 18h8M12 22h10" stroke="#2a3355" strokeWidth="1.8" strokeLinecap="round"/>
    </svg>
  );
}
