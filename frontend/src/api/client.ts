// A thin client for the Kasauti API, same origin only.
//
// Every request that changes something carries X-Kasauti-Request: 1, which the server requires
// (backend/kasauti/api/app.py, CrossSiteGuard): a page on another site can't add it without a
// CORS preflight, and the server grants none. Credentials never leave this origin.

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const GUARD = { "X-Kasauti-Request": "1" };

async function failure(response: Response): Promise<ApiError> {
  let detail = `${response.status} ${response.statusText}`;
  try {
    const body: unknown = await response.json();
    if (body && typeof body === "object" && "detail" in body) {
      const d = (body as { detail: unknown }).detail;
      if (typeof d === "string") detail = d;
      else if (Array.isArray(d)) {
        detail = d
          .map((e) => (e && typeof e === "object" && "msg" in e ? String(e.msg) : String(e)))
          .join("; ");
      }
    }
  } catch {
    // not JSON: keep the status line
  }
  return new ApiError(response.status, detail);
}

async function request<T>(method: string, path: string, init: RequestInit = {}): Promise<T> {
  const unsafe = method !== "GET" && method !== "HEAD";
  const response = await fetch(path, {
    ...init,
    method,
    credentials: "same-origin",
    headers: { ...(unsafe ? GUARD : {}), ...(init.headers ?? {}) },
  });
  if (!response.ok) throw await failure(response);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) =>
    request<T>("POST", path, {
      body: body === undefined ? undefined : JSON.stringify(body),
      headers: body === undefined ? {} : { "Content-Type": "application/json" },
    }),
  put: <T>(path: string, body: unknown) =>
    request<T>("PUT", path, {
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
    }),
  delete: <T>(path: string) => request<T>("DELETE", path),
  /** One file's bytes as the raw body, its name (a path in a folder or archive) in X-File-Name. */
  sendFile: <T>(path: string, file: Blob, name: string) =>
    request<T>("POST", path, {
      body: file,
      headers: {
        "Content-Type": "application/octet-stream",
        "X-File-Name": encodeURIComponent(name),
      },
    }),
};
