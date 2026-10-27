export const isPublicNotesReadRequest = (req) =>
  req.method === "GET" &&
  (req.path === "/api/notes" || req.path === "/api/notes/stats");
