const DEFAULT_MASK = "********";
const DEFAULT_REDACTION = "[REDACTED]";
const MAX_DEPTH = 8;
const MAX_ARRAY_LENGTH = 50;
const MAX_STRING_LENGTH = 512;

const normalizeKey = (key) => key.toLowerCase().replace(/[^a-z0-9]/g, "");

const maskEmail = (value, redactedValue = DEFAULT_REDACTION) => {
  const separator = value.lastIndexOf("@");
  if (separator <= 0 || separator === value.length - 1) return redactedValue;
  return `${value[0]}***${value.slice(separator)}`;
};

const maskName = (value, redactedValue = DEFAULT_REDACTION) => {
  const visibleCharacter = Array.from(value)[0];
  return visibleCharacter ? `${visibleCharacter}***` : redactedValue;
};

const sanitizeString = (value, redactedValue) => {
  const sanitizedUrls = value.replace(/https?:\/\/[^\s"'<>]+/gi, (url) => {
    if (
      /(?:x-amz-(?:signature|credential|security-token)|x-goog-signature|awsaccesskeyid|[?&]signature=|\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com)/i.test(
        url
      )
    ) {
      return redactedValue;
    }
    return url.replace(
      /([?&](?:access_token|refresh_token|token|password|signature)=)[^&#\s]*/gi,
      `$1${redactedValue}`
    );
  });

  return sanitizedUrls
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*/gi, (_match, scheme) =>
      `${scheme || "Authorization"} ${redactedValue}`
    )
    .replace(/\bs3:\/\/[^\s"'<>]+/gi, redactedValue)
    .replace(/\bmongodb(?:\+srv)?:\/\/[^\s"'<>]+/gi, redactedValue)
    .replace(/\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b/g, redactedValue)
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, redactedValue)
    .replace(
      /\b((?:AWS|MONGO|DATABASE|JWT|REDIS)_[A-Z0-9_]*(?:KEY|SECRET|TOKEN|URI|URL|PASSWORD|CREDENTIAL)[A-Z0-9_]*\s*=\s*)["']?[^\s,;]+/gi,
      (_match, prefix) => `${prefix}${redactedValue}`
    )
    .replace(
      /\b((?:password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*)["']?[^,\s;&"'<>]+/gi,
      (_match, prefix) => `${prefix}${redactedValue}`
    )
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, (email) =>
      maskEmail(email, redactedValue)
    )
    .replace(
      /([?&](?:access_token|refresh_token|token|password|signature)=)[^&#\s]*/gi,
      `$1${redactedValue}`
    )
    .slice(0, MAX_STRING_LENGTH);
};

const classifyKey = (key, options) => {
  const normalized = normalizeKey(key);
  if (options.redactKeys.has(normalized)) return "redact";
  if (options.sensitiveKeys.has(normalized)) return "mask";
  if (normalized === "email" || normalized.endsWith("email")) return "email";
  if (
    ["name", "firstname", "lastname", "fullname", "displayname", "username"].includes(normalized)
  ) {
    return "name";
  }
  if (
    /password|passwd|token|authorization|cookie|session(?:id)?|^sid$|secret|credential|privatekey|accesskey|apikey|clientkey|connectionstring|mongouri|jwt/.test(
      normalized
    )
  ) {
    return "mask";
  }
  if (
    /(?:presigned|signed|signature|uploadurl|downloadurl|profilephotourl|s3key|objectkey|noteid|uploadedby|bucket(?:arn|name)?|s3bucket|s3url|objecturl|aws|mongo(?:db)?(?:uri|url|connectionstring)|databaseurl)/.test(
      normalized
    )
  ) {
    return "redact";
  }
  if (
    /(?:phone|mobile|address|dateofbirth|birthdate|studentid)$/.test(normalized) ||
    /^(?:notes?|note(?:content|text|description|body|title)|file(?:data|contents?|buffer))$/.test(
      normalized
    )
  ) {
    return "redact";
  }
  if (
    [
      "address",
      "phone",
      "phonenumber",
      "mobile",
      "dateofbirth",
      "birthdate",
      "dob",
      "ssn",
      "studentid",
      "userid",
      "university",
      "course",
      "year",
      "q",
      "query",
      "search",
      "searchtext",
      "notes",
      "note",
      "content",
      "description",
      "data",
      "payload",
      "text",
      "transcript",
      "document",
      "body",
      "title",
      "filename",
      "file",
      "filedata",
      "filecontent",
      "buffer",
      "attachment",
      "raw",
      "v",
      "encryptedkey",
      "encrypteddata",
      "ciphertext",
      "authorizationpayload",
    ].includes(normalized)
  ) {
    return "redact";
  }
  return undefined;
};

export const createDataMasker = ({
  sensitiveKeys = [],
  redactKeys = [],
  maskedValue = DEFAULT_MASK,
  redactedValue = DEFAULT_REDACTION,
} = {}) => {
  const options = {
    sensitiveKeys: new Set(sensitiveKeys.map(normalizeKey)),
    redactKeys: new Set(redactKeys.map(normalizeKey)),
  };
  const sanitize = (value, depth, ancestors) => {
    if (value === null || value === undefined) return value;
    if (typeof value === "string") return sanitizeString(value, redactedValue);
    if (typeof value === "number" || typeof value === "boolean") return value;
    if (typeof value === "bigint") return value.toString();
    if (typeof value === "function" || typeof value === "symbol") return redactedValue;
    if (Buffer.isBuffer(value)) return redactedValue;
    if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value.toISOString();
    if (depth >= MAX_DEPTH) return redactedValue;
    if (ancestors.has(value)) return "[Circular]";

    ancestors.add(value);
    let result;
    if (Array.isArray(value)) {
      result = value
        .slice(0, MAX_ARRAY_LENGTH)
        .map((item) => sanitize(item, depth + 1, ancestors));
      if (value.length > MAX_ARRAY_LENGTH) result.push("[TRUNCATED]");
    } else {
      result = {};
      for (const [key, nestedValue] of Object.entries(value)) {
        const classification = classifyKey(key, options);
        let safeValue;
        switch (classification) {
          case "email":
            safeValue = typeof nestedValue === "string"
              ? maskEmail(nestedValue, redactedValue)
              : redactedValue;
            break;
          case "name":
            safeValue = typeof nestedValue === "string"
              ? maskName(nestedValue, redactedValue)
              : redactedValue;
            break;
          case "mask":
            safeValue = maskedValue;
            break;
          case "redact":
            safeValue = redactedValue;
            break;
          default:
            safeValue = sanitize(nestedValue, depth + 1, ancestors);
        }
        Object.defineProperty(result, key, {
          value: safeValue,
          enumerable: true,
          configurable: true,
          writable: true,
        });
      }
    }
    ancestors.delete(value);
    return result;
  };

  return (value) => sanitize(value, 0, new WeakSet());
};

export const maskSensitiveData = (value, options) => createDataMasker(options)(value);
