// REST client. The session token arrives in the URL fragment once and is exchanged for an
// HttpOnly cookie; the fragment is then removed from the address bar.

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export async function startSession() {
  const match = location.hash.match(/token=([\w-]+)/);
  if (!match) return;
  await fetch("/api/session", { method: "POST", headers: { "X-Netgrapher-Token": match[1] } });
  history.replaceState(null, "", location.pathname);
}

export async function api(method, path, body) {
  const options = { method, headers: {}, credentials: "same-origin" };
  if (body instanceof Blob || body instanceof ArrayBuffer) {
    options.body = body;
    options.headers["Content-Type"] = "application/octet-stream";
  } else if (body !== undefined) {
    options.body = JSON.stringify(body);
    options.headers["Content-Type"] = "application/json";
  }
  const response = await fetch(path, options);
  if (!response.ok) {
    let message = response.statusText;
    try {
      const detail = (await response.json()).detail;
      message = typeof detail === "string" ? detail : JSON.stringify(detail);
    } catch (_) {
      // keep the status text
    }
    throw new ApiError(response.status, message);
  }
  return response.json();
}

export const itemPath = (id) => encodeURIComponent(id);
