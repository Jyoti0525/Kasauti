import { useQuery } from "@tanstack/react-query";
import { api } from "./client";
import type { AuditOut, AuditResult, Health, Kb, Upload, UploadBrief, VendorDetail } from "./types";

const STILL_RUNNING = new Set(["queued", "running"]);

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: () => api.get<Health>("/api/health"),
    staleTime: 60_000,
  });
}

export function useKb() {
  return useQuery({
    queryKey: ["kb"],
    queryFn: () => api.get<Kb>("/api/kb"),
    staleTime: Infinity,
  });
}

/** A vendor pack's display name, from the installed packs (its id until they load). */
export function usePackName(): (id: string | null | undefined) => string {
  const { data } = useKb();
  return (id) => {
    if (!id) return "–";
    return data?.vendors.find((v) => v.id === id)?.name ?? id;
  };
}

export function useVendor(packId: string | undefined) {
  return useQuery({
    queryKey: ["kb", "vendor", packId],
    queryFn: () => api.get<VendorDetail>(`/api/kb/vendors/${encodeURIComponent(packId ?? "")}`),
    enabled: Boolean(packId),
    staleTime: Infinity,
  });
}

export function useUploads() {
  return useQuery({
    queryKey: ["uploads"],
    queryFn: () => api.get<UploadBrief[]>("/api/uploads"),
    refetchInterval: (q) =>
      q.state.data?.some((u) => (u.audits.queued ?? 0) + (u.audits.running ?? 0) > 0)
        ? 2000
        : false,
  });
}

/** An upload, polled while its files are recognised or its audits run. */
export function useUpload(uploadId: string | undefined) {
  return useQuery({
    queryKey: ["upload", uploadId],
    queryFn: () => api.get<Upload>(`/api/uploads/${uploadId}`),
    enabled: Boolean(uploadId),
    refetchInterval: (q) => {
      const u = q.state.data;
      if (!u) return false;
      const busy =
        u.recognising > 0 || u.files.some((f) => f.job_state && STILL_RUNNING.has(f.job_state));
      return busy ? 1000 : false;
    },
  });
}

/** Device audits with their summaries: every upload's, or one upload's. */
export function useAudits(uploadId?: string) {
  return useQuery({
    queryKey: ["audits", uploadId ?? "all"],
    queryFn: () => api.get<AuditOut[]>(uploadId ? `/api/audits?upload=${uploadId}` : "/api/audits"),
    refetchInterval: (q) => (q.state.data?.some((a) => STILL_RUNNING.has(a.state)) ? 1500 : false),
  });
}

/** A device's full audit result. A result never changes once written. */
export function useResult(jobId: string | undefined) {
  return useQuery({
    queryKey: ["result", jobId],
    queryFn: () => api.get<AuditResult>(`/api/jobs/${jobId}/result`),
    enabled: Boolean(jobId),
    staleTime: Infinity,
  });
}
