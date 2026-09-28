// Licence gate over every locked npm package (PLAN §19.5; TODO M2.75), the web UI's twin of
// tools/check_licences.py, with the same policy:
//
// * runtime packages (what the built UI ships) must be permissive: MIT, ISC, Apache-2.0, BSD,
//   0BSD, CC0, BlueOak;
// * build and test tools are never distributed, so unmodified MPL-2.0 (lightningcss, which
//   Tailwind compiles with) and CC-BY-4.0 data (caniuse-lite, browser support tables) are
//   accepted there too;
// * fonts (@fontsource packages only) may be SIL OFL-1.1, the licence written for fonts: it allows
//   bundling and embedding with any software and forbids only selling the font on its own. IBM
//   Plex, the UI typeface, is OFL-1.1 (https://github.com/IBM/plex/blob/master/LICENSE.txt);
// * GPL, AGPL, SSPL, BUSL and non-commercial licences fail everywhere, as does a package with no
//   licence stated.
//
// Usage: npm run licences
import { readFileSync } from "node:fs";

const PERMISSIVE =
  /^(MIT|ISC|Apache-2\.0|BSD-2-Clause|BSD-3-Clause|0BSD|CC0-1\.0|BlueOak-1\.0\.0)$/;
const BUILD_ONLY = /^(MPL-2\.0|CC-BY-4\.0)$/;
const FONT = /^OFL-1\.1$/;
const DENIED = /GPL|SSPL|BUSL|NonCommercial|CC-BY-NC/i;

const lock = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"));
const problems = [];
let checked = 0;
for (const [path, entry] of Object.entries(lock.packages)) {
  if (path === "") continue;
  checked += 1;
  const name = path.replace(/^.*node_modules\//, "");
  const licence = entry.license ?? "";
  // An SPDX "A OR B" choice passes if one side does; "A AND B" needs both.
  const parts = licence.replace(/[()]/g, "").split(/\s+(OR|AND)\s+/);
  const either = licence.includes(" OR ");
  const font = /^@fontsource(-variable)?\//.test(name);
  const accept = (id) =>
    PERMISSIVE.test(id) || (entry.dev && BUILD_ONLY.test(id)) || (font && FONT.test(id));
  const ids = parts.filter((p) => p !== "OR" && p !== "AND");
  const ok =
    ids.length > 0 && !DENIED.test(licence) && (either ? ids.some(accept) : ids.every(accept));
  if (!ok) {
    problems.push(
      `${name}@${entry.version}: ${licence || "no licence stated"}${entry.dev ? "" : " (runtime)"}`,
    );
  }
}
if (problems.length) {
  console.error(`licence gate: ${problems.length} package(s) refused`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log(`licence gate: ${checked} packages, all accepted`);
