import { useState } from "react";
import {
  Code2, Scale, ExternalLink, Heart,
  ChevronLeft, Cpu, ShieldCheck, Eye, Lock,
  Gauge, GitBranch, EyeOff, BookOpen,
  Layers, Microscope, Box, Zap, Server,
} from "lucide-react";
import { Card } from "../components/Card";
import { ShieldIcon } from "../components/ShieldIcon";
import { t, getLocale } from "../i18n";
import { topicContentFor, type HelpTopic } from "./aboutContent";
import { APP_VERSION_TAG } from "../app-version";
import aboutBanner from "../../../assets/about1.png";
// v0.1.9 consolidation: the Software Updates card (Tauri updater for
// sentinella.exe itself) moved from this page into Update.tsx, alongside
// the signature update card — "anything that updates" now lives in one
// place. About becomes pure informational content + license + tech stack.

// ── Topic cards shown on Overview ────────────────────────
const topics: { id: HelpTopic; icon: typeof Cpu }[] = [
  { id: "what-is-sentinella", icon: ShieldCheck },
  { id: "what-is-argus",      icon: Layers },
  { id: "why-clamav",         icon: Microscope },
  { id: "why-sandbox",        icon: Box },
  { id: "why-workers",        icon: Server },
  { id: "why-realtime-first", icon: Zap },
  { id: "performance",        icon: Gauge },
  { id: "open-source",        icon: GitBranch },
  { id: "privacy",            icon: EyeOff },
];

// ══════════════════════════════════════════════════════════
//  About Page — overview + help topics
// ══════════════════════════════════════════════════════════

export function AboutPage() {
  const [topic, setTopic] = useState<HelpTopic | null>(null);

  if (topic) {
    return <TopicPage topic={topic} onBack={() => setTopic(null)} />;
  }

  return (
    <div className="page-stack">
      {/* Banner */}
      <Card className="relative h-[260px] overflow-hidden rounded-3xl !p-0">
        <img
          src={aboutBanner}
          alt="Sentinella cinematic banner"
          loading="lazy"
          decoding="async"
          className="absolute inset-0 h-full w-full object-cover object-center"
        />
        <div className="absolute inset-0 bg-gradient-to-r from-black/40 via-black/10 to-black/30" />
        <div className="absolute bottom-6 left-8 flex items-center gap-4">
          <ShieldIcon icon="sentinelAlt" size={48} className="brightness-0 invert opacity-80" />
          <div>
            <p className="text-[20px] font-bold text-white/90 leading-none">Sentinella</p>
            <p className="text-[12px] text-white/50 mt-1.5">{t("app.subtitle")} {APP_VERSION_TAG}</p>
          </div>
        </div>
      </Card>

      {/* Software-updates card moved to Update.tsx in v0.1.9. */}

      {/* Technology + License */}
      <div className="card-grid-2">
        <Card>
          <div className="flex items-center gap-2.5 mb-4">
            <Code2 size={15} className="text-[rgb(var(--accent))]" />
            <h4 className="text-[14px] font-semibold">{t("about.technology")}</h4>
          </div>
          <div className="space-y-3 text-[13px]">
            <AR l={t("about.tech_heuristic")} v="ARGUS" />
            <AR l={t("about.tech_adaptive")} v="ASTRA" />
            <AR l={t("about.tech_signature")} v="ClamAV" />
            <AR l={t("about.tech_sandbox")} v="ETW + Job Object" />
            <AR l={t("about.tech_isolation")} v={t("about.tech_isolation_v")} />
            <AR l={t("about.tech_daemon")} v="Rust" />
            <AR l={t("about.tech_gui")} v="Tauri 2.x" />
            <AR l={t("about.tech_frontend")} v="React + TypeScript" />
            <AR l={t("about.tech_ipc")} v="JSON-RPC 2.0" />
            <AR l={t("about.tech_quarantine")} v="AES-256-GCM" />
            <AR l={t("about.tech_file_analysis")} v="PE / ELF / Script" />
            <AR l={t("about.tech_watcher")} v={t("about.tech_watcher_v")} />
          </div>
        </Card>

        <Card>
          <div className="flex items-center gap-2.5 mb-4">
            <Scale size={15} className="text-[rgb(var(--accent))]" />
            <h4 className="text-[14px] font-semibold">{t("about.license_title")}</h4>
          </div>
          <p className="text-[13px] text-[rgb(var(--t2))] leading-relaxed mb-4">
            {t("about.license_p1")}
          </p>
          <p className="text-[13px] text-[rgb(var(--t2))] leading-relaxed mb-4">
            {t("about.license_p2")}
          </p>
          <div className="flex gap-4">
            <ExtLink label={t("about.source_code")} href="https://github.com/nicfb/sentinella" />
            <ExtLink label="ClamAV" href="https://www.clamav.net/" />
            <ExtLink label="GPLv2" href="https://www.gnu.org/licenses/old-licenses/gpl-2.0.html" />
          </div>
        </Card>
      </div>

      {/* Learn about Sentinella */}
      <div>
        <div className="flex items-center gap-2.5 mb-4 px-1">
          <BookOpen size={15} className="text-[rgb(var(--accent))]" />
          <h4 className="text-[14px] font-semibold">{t("about.learn")}</h4>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {topics.map(tp => (
            <TopicCard
              key={tp.id}
              icon={tp.icon}
              title={t(`about.topic.${tp.id}.title`)}
              teaser={t(`about.topic.${tp.id}.teaser`)}
              onClick={() => setTopic(tp.id)}
            />
          ))}
        </div>
      </div>

      {/* Advanced / future */}
      <div>
        <div className="flex items-center gap-2.5 mb-3 px-1">
          <Cpu size={14} className="text-[rgb(var(--t3))]/60" />
          <h4 className="text-[13px] font-medium text-[rgb(var(--t3))]">{t("about.for_devs")}</h4>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <TopicCard icon={Cpu} title={t("about.tech_arch_title")} teaser={t("about.tech_arch_teaser")} onClick={() => setTopic("technical-architecture")} />
          <PlaceholderCard icon={Eye} label={t("about.arch_diagrams")} />
          <PlaceholderCard icon={Lock} label={t("about.changelog")} />
        </div>
      </div>

      <p className="text-center text-[11px] text-[rgb(var(--t3))]/20 flex items-center justify-center gap-1 mt-2">
        {t("about.made_with")} <Heart size={10} className="text-[rgb(var(--red))]" /> {t("about.by_community")}
      </p>
    </div>
  );
}

// ══════════════════════════════════════════════════════════
//  Topic detail page
// ══════════════════════════════════════════════════════════

function TopicPage({ topic, onBack }: { topic: HelpTopic; onBack: () => void }) {
  const content = topicContentFor(getLocale())[topic];
  if (!content) return null;

  return (
    <div className="page-stack">
      {/* Back button */}
      <button
        onClick={onBack}
        className="flex items-center gap-1.5 text-[12px] text-[rgb(var(--t3))] hover:text-[rgb(var(--accent))] transition-colors cursor-pointer w-fit"
      >
        <ChevronLeft size={14} />
        {t("about.back")}
      </button>

      {/* Header */}
      <Card>
        <div className="flex items-center gap-3 mb-5">
          <div className="w-9 h-9 rounded-lg bg-[rgb(var(--accent))]/10 flex items-center justify-center">
            <content.icon size={18} className="text-[rgb(var(--accent))]" />
          </div>
          <div>
            <h3 className="text-[16px] font-semibold">{content.title}</h3>
            <p className="text-[12px] text-[rgb(var(--t3))]">{content.subtitle}</p>
          </div>
        </div>

        <div className="space-y-6">
          {content.sections.map((section, i) => (
            <HelpSection key={i} heading={section.heading} body={section.body} />
          ))}
        </div>
      </Card>
    </div>
  );
}


// ══════════════════════════════════════════════════════════
//  Small presentational components
// ══════════════════════════════════════════════════════════

function AR({ l, v }: { l: string; v: string }) {
  return (
    <div className="flex justify-between">
      <span className="text-[rgb(var(--t3))]">{l}</span>
      <span className="font-medium text-[12px] bg-[rgb(var(--raised))]/20 px-2 py-0.5 rounded text-[rgb(var(--t2))]">{v}</span>
    </div>
  );
}

function ExtLink({ label, href }: { label: string; href: string }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="text-[11px] text-[rgb(var(--accent))] flex items-center gap-1 hover:underline">
      <ExternalLink size={10} />{label}
    </a>
  );
}

function TopicCard({ icon: Icon, title, teaser, onClick }: { icon: typeof Cpu; title: string; teaser: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="glass-card p-5 text-left cursor-pointer transition-all hover:translate-y-[-1px] group"
    >
      <div className="flex items-center gap-2.5 mb-2.5">
        <div className="w-7 h-7 rounded-md bg-[rgb(var(--accent))]/8 flex items-center justify-center">
          <Icon size={14} className="text-[rgb(var(--accent))]" />
        </div>
        <h5 className="text-[13px] font-semibold group-hover:text-[rgb(var(--accent))] transition-colors">{title}</h5>
      </div>
      <p className="text-[12px] text-[rgb(var(--t3))] leading-relaxed">{teaser}</p>
    </button>
  );
}

function HelpSection({ heading, body }: { heading: string; body: string[] }) {
  return (
    <div>
      {heading && <h4 className="text-[13px] font-semibold text-[rgb(var(--t1))] mb-2.5">{heading}</h4>}
      <div className="space-y-2.5">
        {body.map((paragraph, i) => (
          <p key={i} className="text-[13px] text-[rgb(var(--t2))] leading-[1.75]">{paragraph}</p>
        ))}
      </div>
    </div>
  );
}

function PlaceholderCard({ icon: Icon, label }: { icon: typeof Eye; label: string }) {
  return (
    <div className="glass-card p-5 opacity-40 cursor-default">
      <div className="flex items-center gap-2.5 mb-2.5">
        <div className="w-7 h-7 rounded-md bg-[rgb(var(--raised))]/10 flex items-center justify-center">
          <Icon size={14} className="text-[rgb(var(--t3))]" />
        </div>
        <h5 className="text-[13px] font-semibold text-[rgb(var(--t3))]">{label}</h5>
      </div>
      <p className="text-[12px] text-[rgb(var(--t3))]">
        {t("about.coming_soon")}
      </p>
    </div>
  );
}
