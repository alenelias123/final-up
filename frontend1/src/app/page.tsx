"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

type ScanMode = "pentest" | "enterprise";

const INDUSTRIES = [
  "healthcare",
  "finance",
  "ecommerce",
  "government",
  "education",
  "technology",
  "manufacturing",
  "retail",
  "other",
];

const COMPLIANCE_OPTIONS = [
  "PCI-DSS",
  "HIPAA",
  "SOC2",
  "ISO27001",
  "GDPR",
  "NIST",
  "FedRAMP",
];

export default function HomePage() {
  const router = useRouter();
  const [mode, setMode] = useState<ScanMode>("pentest");
  const [url, setUrl] = useState("");
  const [cookie, setCookie] = useState("");
  const [authHeader, setAuthHeader] = useState("");
  const [maxDepth, setMaxDepth] = useState(2);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Enterprise-mode fields
  const [companyName, setCompanyName] = useState("");
  const [industry, setIndustry] = useState("");
  const [techStack, setTechStack] = useState("");
  const [knownAssetRanges, setKnownAssetRanges] = useState("");
  const [selectedCompliance, setSelectedCompliance] = useState<string[]>([]);
  const [minSeverity, setMinSeverity] = useState("");

  function toggleCompliance(fw: string) {
    setSelectedCompliance((prev) =>
      prev.includes(fw) ? prev.filter((f) => f !== fw) : [...prev, fw]
    );
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const body: Record<string, unknown> = {
        url,
        scan_mode: mode,
        scan_config: { max_depth: maxDepth },
      };
      if (cookie || authHeader) {
        body.auth_config = {
          ...(cookie ? { cookie_header: cookie } : {}),
          ...(authHeader ? { authorization_header: authHeader } : {}),
        };
      }

      if (mode === "enterprise") {
        const profile: Record<string, unknown> = {};
        if (companyName) profile.company_name = companyName;
        if (industry) profile.industry = industry;
        if (techStack.trim()) {
          profile.tech_stack = techStack
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean);
        }
        if (knownAssetRanges.trim()) {
          profile.known_asset_ranges = knownAssetRanges
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean);
        }
        if (selectedCompliance.length > 0) {
          profile.compliance_frameworks = selectedCompliance;
        }
        if (minSeverity) profile.min_severity_filter = minSeverity;
        if (Object.keys(profile).length > 0) {
          body.company_profile = profile;
        }
      }

      const res = await fetch(`${API_BASE}/api/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to create scan");
      }
      const data = await res.json();
      router.push(`/scans/${data.scan_id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-3xl font-bold text-white mb-2">New Scan</h1>
      <p className="text-gray-400 mb-6">
        Enter a target URL to enumerate subdomains, crawl endpoints, and detect
        security issues.
      </p>

      {/* Mode Toggle */}
      <div className="mb-8">
        <div className="flex rounded-xl overflow-hidden border border-gray-700 w-full">
          <button
            type="button"
            onClick={() => setMode("pentest")}
            className={`flex-1 py-3 px-4 text-sm font-semibold transition-colors flex flex-col items-center gap-1 ${
              mode === "pentest"
                ? "bg-red-700 text-white"
                : "bg-gray-900 text-gray-400 hover:text-white hover:bg-gray-800"
            }`}
          >
            <span className="text-lg">🔴</span>
            <span>Pentest Mode</span>
            <span className="text-xs font-normal opacity-75">
              All visible vulnerabilities
            </span>
          </button>
          <div className="w-px bg-gray-700" />
          <button
            type="button"
            onClick={() => setMode("enterprise")}
            className={`flex-1 py-3 px-4 text-sm font-semibold transition-colors flex flex-col items-center gap-1 ${
              mode === "enterprise"
                ? "bg-blue-700 text-white"
                : "bg-gray-900 text-gray-400 hover:text-white hover:bg-gray-800"
            }`}
          >
            <span className="text-lg">🏢</span>
            <span>Enterprise Mode</span>
            <span className="text-xs font-normal opacity-75">
              Tailored to your company profile
            </span>
          </button>
        </div>

        {mode === "pentest" && (
          <p className="mt-2 text-xs text-gray-500">
            <span className="text-red-400 font-semibold">Pentest mode</span>:
            Reports every detected vulnerability without filtering — ideal for
            full-coverage security assessments.
          </p>
        )}
        {mode === "enterprise" && (
          <p className="mt-2 text-xs text-gray-500">
            <span className="text-blue-400 font-semibold">Enterprise mode</span>:
            Tailors findings to your industry and compliance requirements,
            boosts severity for relevant risks, and adds compliance control
            references to every finding.
          </p>
        )}
      </div>

      <form onSubmit={handleSubmit} className="space-y-5">
        {/* Target URL */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">
            Target URL <span className="text-red-400">*</span>
          </label>
          <input
            type="text"
            required
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        {/* Cookie Header */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">
            Cookie Header{" "}
            <span className="text-gray-500 text-xs">
              (optional, for authenticated crawl)
            </span>
          </label>
          <input
            type="text"
            value={cookie}
            onChange={(e) => setCookie(e.target.value)}
            placeholder="session=abc123; csrf=xyz"
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        {/* Authorization Header */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">
            Authorization Header{" "}
            <span className="text-gray-500 text-xs">(optional)</span>
          </label>
          <input
            type="text"
            value={authHeader}
            onChange={(e) => setAuthHeader(e.target.value)}
            placeholder="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        {/* Max Crawl Depth */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">
            Max Crawl Depth
          </label>
          <select
            value={maxDepth}
            onChange={(e) => setMaxDepth(Number(e.target.value))}
            className="bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            {[1, 2, 3, 4, 5].map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
        </div>

        {/* Enterprise-only fields */}
        {mode === "enterprise" && (
          <div className="border border-blue-800/60 rounded-xl p-5 space-y-4 bg-blue-950/20">
            <h2 className="text-sm font-semibold text-blue-300 uppercase tracking-wide">
              🏢 Company Profile
            </h2>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Company Name
              </label>
              <input
                type="text"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                placeholder="Acme Corp"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Industry
              </label>
              <select
                value={industry}
                onChange={(e) => setIndustry(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">— Select industry —</option>
                {INDUSTRIES.map((i) => (
                  <option key={i} value={i}>
                    {i.charAt(0).toUpperCase() + i.slice(1)}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Tech Stack{" "}
                <span className="text-gray-500 text-xs">
                  (comma-separated, e.g. nginx, django, postgres)
                </span>
              </label>
              <input
                type="text"
                value={techStack}
                onChange={(e) => setTechStack(e.target.value)}
                placeholder="nginx, django, postgres, redis"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Known Asset IP Ranges{" "}
                <span className="text-gray-500 text-xs">
                  (comma-separated CIDR blocks)
                </span>
              </label>
              <input
                type="text"
                value={knownAssetRanges}
                onChange={(e) => setKnownAssetRanges(e.target.value)}
                placeholder="192.168.1.0/24, 10.0.0.0/8"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Compliance Frameworks
              </label>
              <div className="flex flex-wrap gap-2">
                {COMPLIANCE_OPTIONS.map((fw) => (
                  <button
                    key={fw}
                    type="button"
                    onClick={() => toggleCompliance(fw)}
                    className={`px-3 py-1 rounded-full text-xs font-semibold border transition-colors ${
                      selectedCompliance.includes(fw)
                        ? "bg-blue-600 border-blue-500 text-white"
                        : "border-gray-700 text-gray-400 hover:text-white hover:border-gray-500"
                    }`}
                  >
                    {fw}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Minimum Severity to Report{" "}
                <span className="text-gray-500 text-xs">
                  (filter out lower-severity findings)
                </span>
              </label>
              <select
                value={minSeverity}
                onChange={(e) => setMinSeverity(e.target.value)}
                className="bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">— Show all severities —</option>
                <option value="info">Info and above</option>
                <option value="low">Low and above</option>
                <option value="medium">Medium and above</option>
                <option value="high">High and above</option>
                <option value="critical">Critical only</option>
              </select>
            </div>
          </div>
        )}

        {error && (
          <div className="bg-red-900/40 border border-red-700 rounded-lg px-4 py-3 text-red-300 text-sm">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className={`w-full disabled:cursor-not-allowed text-white font-semibold rounded-lg px-6 py-3 transition-colors ${
            mode === "enterprise"
              ? "bg-blue-600 hover:bg-blue-700 disabled:bg-blue-900"
              : "bg-red-700 hover:bg-red-800 disabled:bg-red-900"
          }`}
        >
          {loading
            ? "Starting scan…"
            : mode === "enterprise"
            ? "🏢 Start Enterprise Scan"
            : "🔴 Start Pentest Scan"}
        </button>
      </form>

      <div className="mt-10 bg-gray-900 border border-gray-800 rounded-lg p-5">
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">
          Sample Config
        </h2>
        <pre className="text-xs text-gray-300 overflow-x-auto">
          {JSON.stringify(
            mode === "enterprise"
              ? {
                  url: "https://example.com",
                  scan_mode: "enterprise",
                  scan_config: { max_depth: 2 },
                  company_profile: {
                    company_name: "Acme Corp",
                    industry: "finance",
                    tech_stack: ["nginx", "django"],
                    compliance_frameworks: ["PCI-DSS", "SOC2"],
                    min_severity_filter: "medium",
                  },
                }
              : {
                  url: "https://example.com",
                  scan_mode: "pentest",
                  scan_config: { max_depth: 2 },
                  auth_config: { cookie_header: "session=<your-session-cookie>" },
                },
            null,
            2
          )}
        </pre>
      </div>
    </div>
  );
}
