import { logInfo } from "../utils/logger.js";
import { maskSensitiveData } from "../utils/dataMasking.js";

const getRouteTemplate = (req) => {
  const routePath = req.route?.path;
  const path = Array.isArray(routePath) ? routePath[0] : routePath;
  return path === undefined ? "unmatched" : `${req.baseUrl || ""}${path}`;
};

export const apiRequestLogger = (req, res, next) => {
  const startedAt = process.hrtime.bigint();
  let responseBody;
  let routeTemplate;
  const originalJson = res.json;

  res.json = function (body) {
    routeTemplate = getRouteTemplate(req);
    responseBody = maskSensitiveData(body);
    return originalJson.call(this, body);
  };

  res.once("finish", () => {
    const elapsedNanoseconds = process.hrtime.bigint() - startedAt;
    const fileCount = req.file
      ? 1
      : Array.isArray(req.files)
        ? req.files.length
        : req.files && typeof req.files === "object"
          ? Object.values(req.files).reduce(
            (total, files) => total + (Array.isArray(files) ? files.length : 0),
            0
          )
          : 0;
    logInfo("http.request", {
      method: req.method,
      route: routeTemplate || getRouteTemplate(req),
      statusCode: res.statusCode,
      durationMs: Number(elapsedNanoseconds / 1_000_000n),
      queryParameters: maskSensitiveData(req.query),
      requestBody: maskSensitiveData(req.body),
      ...(fileCount > 0 ? { uploadedFiles: fileCount } : {}),
      ...(responseBody === undefined ? {} : { response: responseBody }),
    });
  });

  next();
};
