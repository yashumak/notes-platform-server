const getRequestPath = (req) =>
  (req.originalUrl || `${req.baseUrl || ""}${req.path || ""}`).split("?")[0].replace(/\/+$/, "") ||
  "/";

export const hasNoteSearchCriteria = (req) =>
  ["q", "university", "course", "subject", "studyType", "year"].some((key) => {
    const value = req.query?.[key];
    return Array.isArray(value)
      ? value.some((entry) => typeof entry === "string" && entry.trim().length > 0)
      : typeof value === "string" && value.trim().length > 0;
  });

export const isPublicNotesListRequest = (req) =>
  req.method === "GET" && getRequestPath(req) === "/api/notes";

export const isDedicatedRateLimitRequest = (req) => {
  const path = getRequestPath(req);
  if (
    path === "/api/auth/login" ||
    path === "/api/auth/register" ||
    path === "/api/auth/change-password"
  ) {
    return true;
  }
  if (req.method === "GET" && path === "/api/notes") return true;
  return (
    (req.method === "POST" && path === "/api/notes/upload/presign") ||
    (req.method === "POST" && path === "/api/notes/upload")
  );
};
