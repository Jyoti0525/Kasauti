# Kasauti web UI

React 19, TypeScript, Vite and Tailwind 4 (TODO M2.75–M2.83). `kasauti serve` serves the build
(`dist/`) from the same origin as the API, under a content security policy with no inline script
or style and nothing from another origin. The platform makes no network calls: no CDN, no
telemetry, and its typeface (IBM Plex, SIL OFL-1.1) is bundled with the build.

Design system: "basalt and brass" (`src/index.css`). Basalt frames the product, and brass marks
the brand and the one primary action on a screen. Verdicts have their own hues and shapes
(PASS jade ✓, FAIL vermilion ✕, REVIEW indigo, N/A slate), and severity is one ramp shown as a
four-bar glyph. Tokens switch with the system's light or dark setting. The logo lives in
`src/components/Brand.tsx`.

```bash
npm ci            # exactly what package-lock.json says
npm run build     # type-check, then build dist/ for `kasauti serve`
npm run dev       # http://127.0.0.1:5173, proxying /api to a running `kasauti serve`
```

Checks, all run in CI (job `web`):

```bash
npm run licences      # every locked package against the licence policy (PLAN §19.5)
npm audit --audit-level=high
npm run lint          # eslint, including a ban on rendering HTML from strings
npm run format:check  # prettier
npm run typecheck     # tsc, strict
npm test              # Vitest: fleet scoring, the evidence viewer, labels
```

Runtime dependencies: React, React DOM, React Router, TanStack Query and lucide (MIT/ISC), and the
IBM Plex fonts (OFL-1.1). Charts are plain SVG, and the configuration viewer is rebuilt from the
audit's masked evidence: Kasauti keeps no copy of an uploaded file.

| Screen                     | Route           | Source                                                  |
| -------------------------- | --------------- | ------------------------------------------------------- |
| Overview                   | `/`             | `src/pages/Dashboard.tsx`, `src/lib/fleet.ts`           |
| New audit                  | `/audits/new`   | `src/pages/NewAudit.tsx`, `src/components/DropZone.tsx` |
| Audits                     | `/audits`       | `src/pages/Audits.tsx`                                  |
| Audit results              | `/uploads/:id`  | `src/pages/UploadResults.tsx`                           |
| Device view and provenance | `/devices/:job` | `src/pages/Device.tsx`, `src/pages/device/`             |
| Knowledge base             | `/knowledge`    | `src/pages/KnowledgeBase.tsx`                           |
| Rules and frameworks       | `/rules`        | `src/pages/Rules.tsx`                                   |
