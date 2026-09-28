import { BadgeCheck, Clock } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router";
import { useKb, useVendor } from "../api/hooks";
import { Meter } from "../components/charts";
import {
  Card,
  ErrorBox,
  Loading,
  Mono,
  PageHeader,
  Prose,
  SearchBox,
  Tabs,
  Tag,
  cx,
} from "../components/ui";
import { shortHash, show, titleCase } from "../lib/format";

// The structural families (backend/kasauti/shape/model.py, ShapeFamily), for people.
const SHAPES: Record<string, string> = {
  indent: "Indented CLI",
  brace: "Curly-brace hierarchy",
  set_path: "Set commands",
  block_edit: "config / edit blocks",
  path_command: "Path commands",
  xml: "XML",
  json_yaml: "JSON or YAML",
  flat: "Flat lines",
};

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
        subtitle="What Kasauti knows about each vendor: how to recognise its files, how each configuration line maps into the vendor-neutral model, and the vendor's documented defaults."
        meta={
          <span title={kb.data.kb_version}>
            Version <span className="font-mono">{shortHash(kb.data.kb_version, 12)}</span>
          </span>
        }
      />
      <div className="grid gap-6 lg:grid-cols-[17rem_1fr]">
        <nav className="space-y-1.5" aria-label="Vendor packs">
          {kb.data.vendors.map((v) => {
            const active = v.id === selected;
            return (
              <Link
                key={v.id}
                to={`/knowledge/${v.id}`}
                aria-current={active ? "page" : undefined}
                className={cx(
                  "relative block rounded-xl border px-4 py-3 transition-colors",
                  active
                    ? "border-line-strong bg-surface shadow-[inset_3px_0_0_var(--brass)]"
                    : "border-transparent hover:border-line hover:bg-surface",
                )}
              >
                <div className="text-[12px] text-muted">{v.vendor}</div>
                <div className="font-semibold">{v.os_family}</div>
                <div className="mt-2 flex items-center gap-2">
                  <Meter
                    value={v.approved}
                    max={Math.max(1, v.mappings)}
                    tone="pass"
                    className="flex-1"
                  />
                  <span className="figure text-[12px] text-muted">
                    {v.approved}/{v.mappings}
                  </span>
                </div>
                <div className="mt-1 text-[12px] text-faint">
                  mappings approved · {v.defaults} defaults
                </div>
              </Link>
            );
          })}
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
      <Card className="mb-6">
        <div className="text-[12.5px] text-muted">{vendor.vendor}</div>
        <h2 className="text-[20px] font-semibold tracking-[-0.01em]">{vendor.name}</h2>
        <p className="mt-2 max-w-3xl text-[14px] leading-relaxed text-muted">
          <Prose text={vendor.description} />
        </p>
        <dl className="mt-5 grid grid-cols-2 gap-4 border-t border-line pt-4 sm:grid-cols-4">
          <Fact label="Pack">
            <Mono>
              {vendor.id} v{vendor.pack_version}
            </Mono>
          </Fact>
          <Fact label="File shape">
            {SHAPES[vendor.shape_family] ?? titleCase(vendor.shape_family)}
          </Fact>
          <Fact label="Fingerprints">{vendor.signatures}</Fact>
          <Fact label="Device role">
            {vendor.default_role ? titleCase(vendor.default_role) : "From the configuration"}
          </Fact>
        </dl>
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
          <SearchBox
            value={query}
            onChange={setQuery}
            placeholder="Search patterns and objects"
            className="mb-4 w-full max-w-sm"
          />
          <Card bodyClass="p-0 overflow-x-auto">
            <table className="data">
              <thead>
                <tr>
                  <th className="w-[22%]">Mapping</th>
                  <th>Pattern</th>
                  <th className="w-[28%]">Writes</th>
                  <th className="w-36">Approval</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((m) => (
                  <tr key={m.id}>
                    <td>
                      <Mono className="font-medium wrap-break-word">{m.id.split("/")[1]}</Mono>
                      <div className="text-[12px] text-faint">
                        v{m.version}
                        {m.os_versions !== "*" && ` · OS ${m.os_versions}`}
                      </div>
                    </td>
                    <td className="min-w-64">
                      {m.context.length > 0 && (
                        <div className="font-mono text-[11.5px] text-faint wrap-break-word">
                          {m.context.join(" › ")} ›
                        </div>
                      )}
                      <div className="font-mono text-[12.5px] wrap-break-word">{m.match}</div>
                    </td>
                    <td className="text-[12.5px] text-muted">
                      {m.entity && <div className="font-medium text-text">{m.entity}</div>}
                      {m.effects.map((e, i) => (
                        <div key={i} className="font-mono text-[11.5px] wrap-break-word">
                          {effectText(e)}
                        </div>
                      ))}
                    </td>
                    <td className="text-[12.5px]">
                      {m.approved_by.length ? (
                        <span className="inline-flex items-center gap-1 text-pass">
                          <BadgeCheck className="size-4 shrink-0" /> {m.approved_by.join(", ")}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-review">
                          <Clock className="size-4 shrink-0" /> awaiting approval
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </>
      ) : (
        <Card bodyClass="p-0 overflow-x-auto">
          <table className="data">
            <thead>
              <tr>
                <th className="w-[26%]">Default</th>
                <th>Attribute and value</th>
                <th className="w-[40%]">Source</th>
              </tr>
            </thead>
            <tbody>
              {defaults.map((d) => (
                <tr key={d.id}>
                  <td>
                    <Mono className="font-medium wrap-break-word">{d.id}</Mono>
                    {d.os_versions !== "*" && (
                      <div className="text-[12px] text-faint">OS {d.os_versions}</div>
                    )}
                  </td>
                  <td>
                    <Tag className="text-text">
                      {d.attr ?? "–"} = {show(d.value)}
                    </Tag>
                  </td>
                  <td className="text-[12.5px] text-muted">
                    <div className="font-medium text-text">{titleCase(d.source)}</div>
                    <div className="wrap-break-word">{d.reference}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[12px] font-medium text-muted">{label}</dt>
      <dd className="mt-0.5 text-[14px]">{children}</dd>
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
