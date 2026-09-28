import { BadgeCheck, Search } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router";
import { useKb, useVendor } from "../api/hooks";
import { Card, ErrorBox, Loading, Mono, PageHeader, Tabs, cx } from "../components/ui";
import { shortHash, show, titleCase } from "../lib/format";

/** Vendor packs and their mappings (TODO M2.82). Versions are kept per mapping; history,
 * diffs and rollback arrive with M3.27, signatures with M5.08. */
export function KnowledgeBase() {
  const { packId } = useParams();
  const kb = useKb();
  if (kb.isPending) return <Loading what="Loading the knowledge base" />;
  if (kb.isError) return <ErrorBox error={kb.error} />;
  const selected = packId ?? kb.data.vendors[0]?.id;
  return (
    <>
      <PageHeader
        title="Knowledge base"
        subtitle={
          <>
            What Kasauti knows about each vendor: how to recognise its files, how each configuration
            line maps into the vendor-neutral model, and the vendor's documented defaults. Version{" "}
            <span className="font-mono">{shortHash(kb.data.kb_version, 12)}</span>.
          </>
        }
      />
      <div className="grid gap-6 lg:grid-cols-[18rem_1fr]">
        <nav className="space-y-2" aria-label="Vendor packs">
          {kb.data.vendors.map((v) => (
            <Link
              key={v.id}
              to={`/knowledge/${v.id}`}
              className={cx(
                "block rounded-xl border px-4 py-3 transition-colors",
                v.id === selected
                  ? "border-gold bg-surface"
                  : "border-line bg-surface hover:border-faint",
              )}
            >
              <div className="font-medium">{v.name}</div>
              <div className="mt-0.5 text-xs text-muted">
                {v.mappings} mappings · {v.defaults} defaults · v{v.pack_version}
              </div>
              <div className="mt-2 h-1 overflow-hidden rounded-full bg-surface-2">
                <div
                  className="h-full bg-pass"
                  style={{ width: `${(100 * v.approved) / Math.max(1, v.mappings)}%` }}
                />
              </div>
              <div className="mt-1 text-[11px] text-faint">
                {v.approved}/{v.mappings} approved
              </div>
            </Link>
          ))}
        </nav>
        {selected && <VendorDetailView packId={selected} />}
      </div>
    </>
  );
}

function VendorDetailView({ packId }: { packId: string }) {
  const detail = useVendor(packId);
  const [tab, setTab] = useState<"mappings" | "defaults">("mappings");
  const [query, setQuery] = useState("");
  if (detail.isPending) return <Loading />;
  if (detail.isError) return <ErrorBox error={detail.error} />;
  const { vendor, mappings, defaults } = detail.data;
  const q = query.toLowerCase();
  const shown = mappings.filter(
    (m) =>
      !q || `${m.id} ${m.match} ${m.context.join(" ")} ${m.entity ?? ""}`.toLowerCase().includes(q),
  );
  return (
    <div className="min-w-0">
      <Card className="mb-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold">{vendor.name}</h2>
            <p className="mt-1 max-w-2xl text-sm text-muted">{vendor.description}</p>
          </div>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm">
            <dt className="text-muted">Pack</dt>
            <dd className="font-mono text-xs">
              {vendor.id} v{vendor.pack_version}
            </dd>
            <dt className="text-muted">File shape</dt>
            <dd>{titleCase(vendor.shape_family)}</dd>
            <dt className="text-muted">Fingerprints</dt>
            <dd>{vendor.signatures}</dd>
            {vendor.default_role && (
              <>
                <dt className="text-muted">Device role</dt>
                <dd>{titleCase(vendor.default_role)}</dd>
              </>
            )}
          </dl>
        </div>
      </Card>
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { id: "mappings", label: "Mappings", count: mappings.length },
          { id: "defaults", label: "Vendor defaults", count: defaults.length },
        ]}
      />
      {tab === "mappings" ? (
        <>
          <label className="mb-3 flex w-80 items-center gap-1.5 rounded-lg border border-line bg-surface px-2 py-1">
            <Search className="size-3.5 text-faint" aria-hidden />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search patterns…"
              className="w-full bg-transparent text-sm outline-none"
            />
          </label>
          <div className="overflow-hidden rounded-xl border border-line bg-surface">
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-muted">
                <tr className="border-b border-line bg-surface-2">
                  <th className="px-4 py-2 font-medium">Mapping</th>
                  <th className="px-3 py-2 font-medium">Pattern</th>
                  <th className="px-3 py-2 font-medium">Writes</th>
                  <th className="px-4 py-2 font-medium">Approval</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((m) => (
                  <tr key={m.id} className="border-b border-line align-top last:border-0">
                    <td className="px-4 py-2">
                      <Mono className="font-medium">{m.id.split("/")[1]}</Mono>
                      <div className="text-[11px] text-faint">
                        v{m.version}
                        {m.os_versions !== "*" && ` · OS ${m.os_versions}`}
                      </div>
                    </td>
                    <td className="max-w-md px-3 py-2">
                      {m.context.length > 0 && (
                        <div className="truncate font-mono text-[11px] text-faint">
                          {m.context.join(" › ")} ›
                        </div>
                      )}
                      <div className="break-words font-mono text-[12px]">{m.match}</div>
                    </td>
                    <td className="px-3 py-2 text-xs text-muted">
                      {m.entity && <div className="font-medium text-text">{m.entity}</div>}
                      {m.effects.map((e, i) => (
                        <div key={i} className="font-mono text-[11px]">
                          {effectText(e)}
                        </div>
                      ))}
                    </td>
                    <td className="px-4 py-2 text-xs">
                      {m.approved_by.length ? (
                        <span className="inline-flex items-center gap-1 text-pass">
                          <BadgeCheck className="size-3.5" /> {m.approved_by.join(", ")}
                        </span>
                      ) : (
                        <span className="text-review">awaiting approval</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : (
        <div className="overflow-hidden rounded-xl border border-line bg-surface">
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-muted">
              <tr className="border-b border-line bg-surface-2">
                <th className="px-4 py-2 font-medium">Default</th>
                <th className="px-3 py-2 font-medium">Attribute = value</th>
                <th className="px-4 py-2 font-medium">Source</th>
              </tr>
            </thead>
            <tbody>
              {defaults.map((d) => (
                <tr key={d.id} className="border-b border-line align-top last:border-0">
                  <td className="px-4 py-2">
                    <Mono className="font-medium">{d.id}</Mono>
                    {d.os_versions !== "*" && (
                      <div className="text-[11px] text-faint">OS {d.os_versions}</div>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {d.attr ?? "–"} = {show(d.value)}
                  </td>
                  <td className="max-w-md px-4 py-2 text-xs text-muted">
                    <div className="font-medium text-text">{titleCase(d.source)}</div>
                    <div className="break-words">{d.reference}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const ATTR = /^[A-Z][A-Za-z0-9]+\.[a-z][a-z0-9_]*$/;

/** One effect as a line: its verb and the attribute it writes (``set LocalUser.hash_type``), with
 * the value it asserts, if any. */
function effectText(e: Record<string, unknown>): string {
  const verb = Object.keys(e).find((k) => typeof e[k] === "string" && ATTR.test(e[k] as string));
  if (!verb) return JSON.stringify(e);
  return `${verb} ${e[verb] as string}${"value" in e ? ` = ${show(e.value)}` : ""}`;
}
