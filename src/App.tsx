import { useEffect, useMemo, useRef, useState } from "react";
import { Capacitor } from "@capacitor/core";
import { Clipboard } from "@capacitor/clipboard";
import { Filesystem, Directory, Encoding } from "@capacitor/filesystem";
import { Share } from "@capacitor/share";

type Screen = "home" | "settings";
type SettingsTab = "connection" | "appearance";
type Theme = "rose" | "violet" | "midnight";
type ToastTone = "success" | "info" | "error";
type Protocol = "VLESS" | "VMESS" | "TROJAN" | "SS" | "WIREGUARD" | "JSON";

type ConnectionProfile = {
  id: string;
  name: string;
  protocol: Protocol;
  endpoint: string;
  config: string;
};

type ToastMessage = {
  id: number;
  text: string;
  tone: ToastTone;
};

const PROFILE_STORAGE_KEY = "2n5a.profiles";
const SELECTED_PROFILE_KEY = "2n5a.selected-profile";
const THEME_STORAGE_KEY = "2n5a.theme";
const MOTION_STORAGE_KEY = "2n5a.motion";

function readStorage<T>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback;
  try {
    const value = window.localStorage.getItem(key);
    return value ? (JSON.parse(value) as T) : fallback;
  } catch {
    return fallback;
  }
}

function writeStorage(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Keep the interface usable when browser storage is unavailable.
  }
}

function clearStorage(key: string) {
  try {
    window.localStorage.removeItem(key);
  } catch {
    // Storage can be disabled by the browser or privacy settings.
  }
}

function createId() {
  return typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function safeDecode(value: string) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function decodeBase64(value: string) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return atob(padded);
}

function parseConnection(input: string): ConnectionProfile {
  const raw = input.trim();
  if (!raw) throw new Error("أدخل رابط اتصال أو ملف إعدادات أولاً.");

  const wireGuard = /^\s*\[Interface\]\s*$/im.test(raw);
  if (wireGuard) {
    const hasPeer = /^\s*\[Peer\]\s*$/im.test(raw);
    const hasPrivateKey = /^\s*PrivateKey\s*=\s*\S+/im.test(raw);
    const hasPublicKey = /^\s*PublicKey\s*=\s*\S+/im.test(raw);
    const endpoint = raw.match(/^\s*Endpoint\s*=\s*(\S+)/im)?.[1];
    if (!hasPeer || !hasPrivateKey || !hasPublicKey || !endpoint) {
      throw new Error("ملف WireGuard غير مكتمل. تحقق من المفاتيح ونقطة النهاية.");
    }
    return {
      id: createId(),
      name: "WireGuard",
      protocol: "WIREGUARD",
      endpoint,
      config: raw,
    };
  }

  const scheme = raw.match(/^([a-z][a-z0-9+.-]*):\/\//i)?.[1]?.toLowerCase();
  if (scheme && ["vless", "vmess", "trojan", "ss"].includes(scheme)) {
    const protocol = scheme.toUpperCase() as Protocol;

    if (scheme === "vmess") {
      try {
        const encoded = raw.slice(raw.indexOf("://") + 3).split("#")[0];
        const data = JSON.parse(decodeBase64(encoded)) as {
          add?: string;
          port?: string | number;
          ps?: string;
          id?: string;
        };
        if (!data.add || !data.port || !data.id) throw new Error("missing fields");
        return {
          id: createId(),
          name: data.ps || "نقطة VMess",
          protocol,
          endpoint: `${data.add}:${data.port}`,
          config: raw,
        };
      } catch {
        throw new Error("رابط VMess غير صالح أو لا يحتوي بيانات الخادم المطلوبة.");
      }
    }

    let candidate = raw;
    let parsed: URL | null = null;
    try {
      parsed = new URL(candidate);
    } catch {
      parsed = null;
    }

    if (scheme === "ss" && (!parsed?.hostname || !parsed.port)) {
      try {
        const encoded = raw.slice(raw.indexOf("://") + 3).split("#")[0];
        const decoded = decodeBase64(encoded);
        if (decoded.includes("@")) {
          candidate = `ss://${decoded}${raw.includes("#") ? `#${raw.split("#").slice(1).join("#")}` : ""}`;
          parsed = new URL(candidate);
        }
      } catch {
        parsed = null;
      }
    }

    if (!parsed?.hostname || !parsed.port) {
      throw new Error("تعذر قراءة الخادم والمنفذ من رابط الاتصال.");
    }
    const port = Number(parsed.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error("رقم المنفذ في رابط الاتصال غير صالح.");
    }
    if (scheme === "vless" && !parsed.username) {
      throw new Error("رابط VLESS لا يحتوي على معرّف المستخدم.");
    }
    if (scheme === "trojan" && !parsed.username) {
      throw new Error("رابط Trojan لا يحتوي على كلمة المرور.");
    }

    const fragment = safeDecode(parsed.hash.replace(/^#/, ""));
    return {
      id: createId(),
      name: fragment || `${protocol} - ${parsed.hostname}`,
      protocol,
      endpoint: `${parsed.hostname}:${port}`,
      config: raw,
    };
  }

  try {
    const data = JSON.parse(raw) as Record<string, unknown>;
    const outbounds = Array.isArray(data.outbounds) ? data.outbounds : [];
    const firstOutbound = (outbounds[0] ?? {}) as {
      settings?: { vnext?: Array<{ address?: string; port?: number }>; servers?: Array<{ address?: string; port?: number }> };
    };
    const server = firstOutbound.settings?.vnext?.[0] ?? firstOutbound.settings?.servers?.[0];
    const knownShape = outbounds.length > 0 || Array.isArray(data.peers) || typeof data.server === "string";
    if (!knownShape) throw new Error("unknown json shape");
    const endpoint = server?.address
      ? `${server.address}${server.port ? `:${server.port}` : ""}`
      : typeof data.server === "string"
        ? data.server
        : "إعداد JSON";
    return {
      id: createId(),
      name: "إعداد اتصال JSON",
      protocol: "JSON",
      endpoint,
      config: raw,
    };
  } catch {
    throw new Error("الصيغة غير مدعومة. استخدم رابط VLESS أو VMess أو Trojan أو SS، أو ملف WireGuard أو JSON صالح.");
  }
}

function Icon({ name, size = 20 }: { name: "settings" | "chevron" | "back" | "paste" | "upload" | "download" | "trash" | "close" | "plus" | "check"; size?: number }) {
  const shared = {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true as const,
  };

  switch (name) {
    case "settings":
      return <svg {...shared}><path d="M12 8.2a3.8 3.8 0 1 0 0 7.6 3.8 3.8 0 0 0 0-7.6Z" /><path d="M19.4 13.5a7.7 7.7 0 0 0 0-3l1.7-1.3-1.7-2.9-2 .8a7.7 7.7 0 0 0-2.6-1.5L14.5 3h-5l-.3 2.6a7.7 7.7 0 0 0-2.6 1.5l-2-.8-1.7 2.9 1.7 1.3a7.7 7.7 0 0 0 0 3l-1.7 1.3 1.7 2.9 2-.8a7.7 7.7 0 0 0 2.6 1.5l.3 2.6h5l.3-2.6a7.7 7.7 0 0 0 2.6-1.5l2 .8 1.7-2.9Z" /></svg>;
    case "chevron":
      return <svg {...shared}><path d="m6 9 6 6 6-6" /></svg>;
    case "back":
      return <svg {...shared}><path d="m15 18-6-6 6-6" /><path d="M9 12h10" /></svg>;
    case "paste":
      return <svg {...shared}><rect x="5" y="5" width="14" height="16" rx="2" /><path d="M9 5.5V4h6v1.5M9 11h6M9 15h6" /></svg>;
    case "upload":
      return <svg {...shared}><path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5" /><path d="M5 13v5a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-5" /></svg>;
    case "download":
      return <svg {...shared}><path d="M12 4v12m0 0 4.5-4.5M12 16l-4.5-4.5" /><path d="M5 17v2a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-2" /></svg>;
    case "trash":
      return <svg {...shared}><path d="M4 7h16M10 11v6m4-6v6M5.5 7l1 13h11l1-13M9 7V4h6v3" /></svg>;
    case "close":
      return <svg {...shared}><path d="m18 6-12 12M6 6l12 12" /></svg>;
    case "plus":
      return <svg {...shared}><path d="M12 5v14M5 12h14" /></svg>;
    case "check":
      return <svg {...shared}><path d="m5 12 4 4L19 6" /></svg>;
  }
}

function BrandMark() {
  return (
    <svg className="brand-mark" viewBox="0 0 40 40" fill="none" aria-hidden="true">
      <path d="M8 30a16 16 0 1 1 24 0" stroke="url(#brand-gradient)" strokeWidth="4" strokeLinecap="round" />
      <path d="M13 27a10 10 0 1 1 14 0" stroke="var(--pink)" strokeWidth="4" strokeLinecap="round" />
      <circle cx="20" cy="21" r="3.2" fill="var(--pink)" />
      <defs><linearGradient id="brand-gradient" x1="6" y1="6" x2="34" y2="34" gradientUnits="userSpaceOnUse"><stop stopColor="var(--purple)" /><stop offset="1" stopColor="var(--pink)" /></linearGradient></defs>
    </svg>
  );
}

function SignalMark() {
  return (
    <svg className="signal-svg" viewBox="0 0 480 480" fill="none" aria-hidden="true">
      <defs>
        <linearGradient id="outer-signal" x1="50" y1="94" x2="410" y2="407" gradientUnits="userSpaceOnUse"><stop stopColor="var(--purple)" /><stop offset="1" stopColor="var(--purple-deep)" /></linearGradient>
        <linearGradient id="inner-signal" x1="128" y1="165" x2="352" y2="352" gradientUnits="userSpaceOnUse"><stop stopColor="var(--pink)" /><stop offset="1" stopColor="var(--pink-deep)" /></linearGradient>
      </defs>
      <path className="outer-ring" d="M118 385a190 190 0 1 1 244 0" stroke="url(#outer-signal)" strokeWidth="43" />
      <path className="inner-ring" d="M158 337a128 128 0 1 1 164 0" stroke="url(#inner-signal)" strokeWidth="43" />
      <circle className="signal-core" cx="240" cy="237" r="46" fill="var(--pink)" />
      <circle className="signal-orbit" cx="240" cy="237" r="70" stroke="var(--pink)" strokeWidth="1.5" />
    </svg>
  );
}

function SwitchRow({
  title,
  description,
  checked,
  onChange,
}: {
  title: string;
  description: string;
  checked: boolean;
  onChange: () => void;
}) {
  return (
    <div className="setting-row">
      <div className="setting-copy">
        <strong>{title}</strong>
        <span>{description}</span>
      </div>
      <button className={`switch ${checked ? "is-on" : ""}`} type="button" role="switch" aria-checked={checked} aria-label={title} onClick={onChange}>
        <span />
      </button>
    </div>
  );
}

export default function App() {
  const [screen, setScreen] = useState<Screen>("home");
  const [settingsTab, setSettingsTab] = useState<SettingsTab>("connection");
  const [profiles, setProfiles] = useState<ConnectionProfile[]>(() => {
    const saved = readStorage<ConnectionProfile[]>(PROFILE_STORAGE_KEY, []);
    return Array.isArray(saved) ? saved.filter((item) => item && typeof item.config === "string") : [];
  });
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(() => readStorage<string | null>(SELECTED_PROFILE_KEY, null));
  const [theme, setTheme] = useState<Theme>(() => readStorage<Theme>(THEME_STORAGE_KEY, "rose"));
  const [animationsEnabled, setAnimationsEnabled] = useState(() => readStorage<boolean>(MOTION_STORAGE_KEY, true));
  const [vpnPreview, setVpnPreview] = useState(false);
  const [sharingPreview, setSharingPreview] = useState(false);
  const [rawConfig, setRawConfig] = useState("");
  const [nodeMenuOpen, setNodeMenuOpen] = useState(false);
  const [toast, setToast] = useState<ToastMessage | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const activeProfile = useMemo(() => profiles.find((profile) => profile.id === selectedProfileId) ?? null, [profiles, selectedProfileId]);

  useEffect(() => {
    writeStorage(PROFILE_STORAGE_KEY, JSON.stringify(profiles));
  }, [profiles]);

  useEffect(() => {
    if (selectedProfileId && !profiles.some((profile) => profile.id === selectedProfileId)) {
      setSelectedProfileId(profiles[0]?.id ?? null);
    }
  }, [profiles, selectedProfileId]);

  useEffect(() => {
    if (selectedProfileId) writeStorage(SELECTED_PROFILE_KEY, JSON.stringify(selectedProfileId));
    else clearStorage(SELECTED_PROFILE_KEY);
  }, [selectedProfileId]);

  useEffect(() => {
    writeStorage(THEME_STORAGE_KEY, JSON.stringify(theme));
  }, [theme]);

  useEffect(() => {
    writeStorage(MOTION_STORAGE_KEY, JSON.stringify(animationsEnabled));
  }, [animationsEnabled]);

  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(() => setToast(null), 3300);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  function showToast(text: string, tone: ToastTone = "info") {
    setToast({ id: Date.now(), text, tone });
  }

  function saveConnection(value: string) {
    try {
      const profile = parseConnection(value);
      const updated = [profile, ...profiles.filter((item) => item.endpoint !== profile.endpoint || item.protocol !== profile.protocol)];
      setProfiles(updated);
      setSelectedProfileId(profile.id);
      setRawConfig("");
      setNodeMenuOpen(false);
      showToast("تم التحقق من الإعداد وحفظه على هذا الجهاز.", "success");
    } catch (error) {
      showToast(error instanceof Error ? error.message : "تعذر قراءة ملف الاتصال.", "error");
    }
  }

  async function pasteConfig() {
    try {
      const value = Capacitor.isNativePlatform()
        ? (await Clipboard.read()).value ?? ""
        : await navigator.clipboard.readText();
      if (!value.trim()) {
        showToast("الحافظة فارغة.", "info");
        return;
      }
      setRawConfig(value);
      showToast("تم لصق الإعداد. راجعه ثم احفظه.", "success");
    } catch {
      showToast("تعذر الوصول إلى الحافظة. الصق النص في الحقل يدوياً.", "info");
    }
  }

  async function importFile(file?: File) {
    if (!file) return;
    try {
      const contents = await file.text();
      setRawConfig(contents);
      saveConnection(contents);
    } catch {
      showToast("تعذر قراءة الملف المحدد.", "error");
    }
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  async function exportSelected() {
    if (!activeProfile) {
      showToast("اختر نقطة اتصال محفوظة أولاً.", "info");
      return;
    }
    const suffix = activeProfile.protocol === "WIREGUARD" ? "conf" : activeProfile.protocol === "JSON" ? "json" : "txt";
    const fileName = `2n5a-${activeProfile.protocol.toLowerCase()}.${suffix}`;
    try {
      if (Capacitor.isNativePlatform()) {
        const saved = await Filesystem.writeFile({
          path: fileName,
          data: activeProfile.config,
          directory: Directory.Cache,
          encoding: Encoding.UTF8,
        });
        await Share.share({ title: fileName, url: saved.uri, dialogTitle: "تصدير الإعداد" });
      } else {
        const blob = new Blob([activeProfile.config], { type: "text/plain;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = fileName;
        link.click();
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      }
      showToast("تم تصدير الإعداد المحدد.", "success");
    } catch {
      showToast("تعذر تصدير الإعداد.", "error");
    }
  }

  function removeProfile(profileId: string) {
    setProfiles((current) => current.filter((profile) => profile.id !== profileId));
    showToast("تم حذف نقطة الاتصال من التخزين المحلي.", "success");
  }

  function handleVpnToggle() {
    if (!activeProfile) {
      setSettingsTab("connection");
      setScreen("settings");
      showToast("أضف نقطة اتصال أولاً لعرض عناصر التحكم.", "info");
      return;
    }
    const next = !vpnPreview;
    setVpnPreview(next);
    showToast(next ? "تغيرت حالة واجهة الاتصال. لا ينشئ المتصفح نفق VPN فعلياً." : "تم إيقاف معاينة حالة الاتصال.", "info");
  }

  function handleSharingToggle() {
    const next = !sharingPreview;
    setSharingPreview(next);
    showToast(next ? "هذه معاينة فقط. مشاركة الشبكة تتطلب تطبيق أندرويد أصلياً." : "تم إيقاف معاينة مشاركة الشبكة.", "info");
  }

  function chooseProfile(profileId: string) {
    setSelectedProfileId(profileId);
    setNodeMenuOpen(false);
    const next = profiles.find((profile) => profile.id === profileId);
    if (next) showToast(`تم اختيار ${next.name}.`, "success");
  }

  return (
    <div className={`app-shell ${screen === "settings" ? "settings-shell" : ""} ${animationsEnabled ? "" : "motion-off"}`} data-theme={theme} dir="rtl">
      {screen === "home" ? (
        <div className="home-page">
          <header className="topbar">
            <div className="brand-lockup" aria-label="2n5a">
              <BrandMark />
              <span className="brand-name">2n5a</span>
            </div>

            <div className="node-picker-wrap">
              <button className={`node-picker ${nodeMenuOpen ? "is-open" : ""}`} type="button" aria-expanded={nodeMenuOpen} onClick={() => setNodeMenuOpen((open) => !open)}>
                <span className={`node-dot ${activeProfile ? "is-ready" : ""}`} />
                <span className="node-name">{activeProfile?.name ?? "اختر نقطة"}</span>
                <Icon name="chevron" size={16} />
              </button>
              {nodeMenuOpen && (
                <div className="node-menu" role="menu">
                  <div className="node-menu-heading">
                    <strong>نقاط الاتصال</strong>
                    <button className="bare-icon" type="button" aria-label="إغلاق القائمة" onClick={() => setNodeMenuOpen(false)}><Icon name="close" size={17} /></button>
                  </div>
                  {profiles.length ? profiles.map((profile) => (
                    <button className="node-menu-item" key={profile.id} type="button" role="menuitem" onClick={() => chooseProfile(profile.id)}>
                      <span className="node-menu-status" />
                      <span><strong>{profile.name}</strong><small>{profile.protocol} · {profile.endpoint}</small></span>
                      {selectedProfileId === profile.id && <Icon name="check" size={17} />}
                    </button>
                  )) : (
                    <p className="node-empty">لا توجد نقاط محفوظة. أضف رابط اتصال من الإعدادات.</p>
                  )}
                  <button className="node-menu-add" type="button" onClick={() => { setNodeMenuOpen(false); setScreen("settings"); setSettingsTab("connection"); }}>
                    <Icon name="plus" size={17} /> إدارة نقاط الاتصال
                  </button>
                </div>
              )}
            </div>

            <button className="icon-button settings-trigger" type="button" aria-label="الإعدادات" onClick={() => { setNodeMenuOpen(false); setScreen("settings"); }}>
              <Icon name="settings" size={23} />
            </button>
          </header>

          <main className="home-main">
            <section className="home-hero" aria-label="حالة الاتصال">
              <div className="hero-stack">
                <div className="signal-visual" data-connected={vpnPreview}>
                  <div className="signal-aura" />
                  <SignalMark />
                </div>
                <div className="connection-state">
                  <span className={`status-light ${vpnPreview ? "is-live" : ""}`} />
                  <span>{vpnPreview ? "معاينة الاتصال نشطة" : activeProfile ? "جاهز للاتصال" : "بانتظار إعداد نقطة اتصال"}</span>
                </div>
              </div>
            </section>

            <section className="home-actions" aria-label="عناصر التحكم">
              <button className={`action-button action-primary ${vpnPreview ? "is-active" : ""}`} type="button" onClick={handleVpnToggle}>
                {vpnPreview ? "إيقاف VPN" : "تشغيل VPN"}
              </button>
              <button className={`action-button action-secondary ${sharingPreview ? "is-active" : ""}`} type="button" onClick={handleSharingToggle}>
                {sharingPreview ? "إيقاف مشاركة الشبكة" : "مشاركة الشبكة"}
              </button>
            </section>

            <footer className="home-footer">
              <div className="footer-line"><span>2N5A</span><i /> <span>الحالة</span><strong>{vpnPreview ? "معاينة نشطة" : "غير متصل"}</strong></div>
              <p>واجهة ويب توضيحية، لا تنشئ نفق VPN أو نقطة اتصال فعلية.</p>
            </footer>
          </main>
        </div>
      ) : (
        <div className="settings-page">
          <header className="settings-topbar">
            <button className="icon-button back-button" type="button" aria-label="العودة للرئيسية" onClick={() => setScreen("home")}><Icon name="back" size={22} /></button>
            <div className="settings-brand"><BrandMark /><span>الإعدادات</span><small>2n5a</small></div>
            <div className="settings-topbar-spacer" />
          </header>

          <main className="settings-content">
            <div className="settings-intro">
              <span className="eyebrow">2N5A / CONTROL</span>
              <h1>إعدادات الاتصال والتطبيق</h1>
              <p>أدر إعداداتك المحلية ومظهر الواجهة من مكان واحد.</p>
            </div>

            <div className="settings-tabs" role="tablist" aria-label="أقسام الإعدادات">
              <button className={settingsTab === "connection" ? "selected" : ""} role="tab" aria-selected={settingsTab === "connection"} type="button" onClick={() => setSettingsTab("connection")}>الاتصال</button>
              <button className={settingsTab === "appearance" ? "selected" : ""} role="tab" aria-selected={settingsTab === "appearance"} type="button" onClick={() => setSettingsTab("appearance")}>المظهر والتطبيق</button>
            </div>

            {settingsTab === "connection" ? (
              <div className="settings-sections">
                <section className="settings-panel">
                  <div className="panel-heading">
                    <div>
                      <span className="panel-kicker">PROFILE MANAGER</span>
                      <h2>كود الاتصال</h2>
                      <p>أدخل رابطاً أو ألصق إعداداً للتحقق منه وحفظه محلياً.</p>
                    </div>
                    <button className="quiet-button paste-button" type="button" onClick={pasteConfig}><Icon name="paste" size={18} /><span>لصق</span></button>
                  </div>

                  <label className="sr-only" htmlFor="connection-config">رابط أو ملف الاتصال</label>
                  <textarea
                    id="connection-config"
                    className="config-input"
                    dir="ltr"
                    spellCheck={false}
                    value={rawConfig}
                    onChange={(event) => setRawConfig(event.target.value)}
                    placeholder="vless://UUID@server.example:443?type=ws#My-Node"
                  />
                  <div className="config-actions">
                    <button className="action-button compact action-primary" type="button" onClick={() => saveConnection(rawConfig)}>حفظ الكود</button>
                    <button className="quiet-button" type="button" onClick={() => fileInputRef.current?.click()}><Icon name="upload" size={18} /> استيراد ملف</button>
                    <input ref={fileInputRef} className="sr-only" type="file" accept=".txt,.json,.conf,.config" onChange={(event) => void importFile(event.target.files?.[0])} />
                  </div>
                  <p className="format-note">يدعم VLESS وVMess وTrojan وShadowsocks وWireGuard وJSON.</p>
                </section>

                <section className="settings-panel saved-panel">
                  <div className="saved-heading">
                    <div>
                      <span className="panel-kicker">LOCAL PROFILES</span>
                      <h2>نقاط الاتصال المحفوظة</h2>
                    </div>
                    <button className="quiet-button export-button" type="button" onClick={exportSelected}><Icon name="download" size={18} /> تصدير المحدد</button>
                  </div>

                  {profiles.length ? (
                    <div className="profile-list">
                      {profiles.map((profile) => (
                        <div className={`profile-row ${selectedProfileId === profile.id ? "is-selected" : ""}`} key={profile.id}>
                          <button className="profile-main" type="button" onClick={() => chooseProfile(profile.id)} aria-pressed={selectedProfileId === profile.id}>
                            <span className="protocol-badge">{profile.protocol === "WIREGUARD" ? "WG" : profile.protocol}</span>
                            <span className="profile-details"><strong>{profile.name}</strong><small dir="ltr">{profile.endpoint}</small></span>
                            {selectedProfileId === profile.id && <span className="selected-mark"><Icon name="check" size={17} /></span>}
                          </button>
                          <button className="bare-icon delete-profile" type="button" aria-label={`حذف ${profile.name}`} onClick={() => removeProfile(profile.id)}><Icon name="trash" size={18} /></button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="empty-profiles">
                      <span className="empty-mark"><Icon name="plus" size={22} /></span>
                      <div><strong>لا توجد نقطة اتصال محفوظة</strong><p>استورد رابط اتصال أو ملف إعدادات لتظهر هنا.</p></div>
                    </div>
                  )}
                  <p className="privacy-note">تبقى الإعدادات في تخزين هذا المتصفح. قد تحتوي على مفاتيح أو بيانات اعتماد سرية.</p>
                </section>

                <section className="settings-panel integration-panel">
                  <div className="panel-heading">
                    <div>
                      <span className="panel-kicker">ANDROID INTEGRATION</span>
                      <h2>تكامل Shizuku وVPN</h2>
                    </div>
                    <span className="web-only-tag">نسخة ويب</span>
                  </div>
                  <div className="integration-row">
                    <div className="integration-copy">
                      <span>صلاحية Shizuku</span>
                      <strong>تتطلب تطبيق أندرويد أصلياً</strong>
                    </div>
                    <button className="quiet-button" type="button" onClick={() => showToast("لا يستطيع المتصفح الوصول إلى Shizuku أو خدمة TUN في أندرويد.", "info")}>التفاصيل</button>
                  </div>
                  <p className="integration-note">هذه الواجهة تدير ملفات الإعداد محلياً فقط. لا تنشئ نفق VPN فعلياً ولا تتحكم في Shizuku أو مشاركة الشبكة.</p>
                </section>
              </div>
            ) : (
              <div className="settings-sections">
                <section className="settings-panel appearance-panel">
                  <div className="panel-heading">
                    <div>
                      <span className="panel-kicker">VISUAL SYSTEM</span>
                      <h2>المظهر وخط التطبيق</h2>
                      <p>اختر لوحة الألوان التي تناسب تجربتك.</p>
                    </div>
                  </div>
                  <div className="theme-options" role="radiogroup" aria-label="لوحة الألوان">
                    {([
                      ["rose", "الوردي الداكن", "#e42bb6", "#8750e7"],
                      ["violet", "بنفسجي ليلي", "#c15ae9", "#6e5ce7"],
                      ["midnight", "فحمي هادئ", "#be69d7", "#6266d9"],
                    ] as const).map(([value, label, pink, purple]) => (
                      <button key={value} className={`theme-option ${theme === value ? "is-selected" : ""}`} type="button" role="radio" aria-checked={theme === value} onClick={() => setTheme(value)}>
                        <span className="theme-swatches"><i style={{ background: pink }} /><i style={{ background: purple }} /></span>
                        <strong>{label}</strong>
                        {theme === value && <span className="theme-check"><Icon name="check" size={16} /></span>}
                      </button>
                    ))}
                  </div>
                </section>

                <section className="settings-panel">
                  <div className="panel-heading">
                    <div>
                      <span className="panel-kicker">PREFERENCES</span>
                      <h2>تفضيلات الواجهة</h2>
                    </div>
                  </div>
                  <div className="preference-list">
                    <SwitchRow title="الحركة البصرية" description="تفعيل النبضات والانتقالات الهادئة." checked={animationsEnabled} onChange={() => setAnimationsEnabled((enabled) => !enabled)} />
                    <div className="setting-row language-row">
                      <div className="setting-copy"><strong>لغة الواجهة</strong><span>اتجاه RTL مضبوط للعربية.</span></div>
                      <span className="language-current">العربية <span>AR</span></span>
                    </div>
                  </div>
                </section>

                <div className="settings-version"><BrandMark /><span>2n5a</span><i /> <span>الإصدار 1.0.0</span></div>
              </div>
            )}
          </main>
        </div>
      )}

      {toast && (
        <div className={`toast-message toast-${toast.tone}`} key={toast.id} role="status" aria-live="polite">
          <span className="toast-indicator" />
          <span>{toast.text}</span>
          <button type="button" aria-label="إغلاق التنبيه" onClick={() => setToast(null)}><Icon name="close" size={17} /></button>
        </div>
      )}
    </div>
  );
}