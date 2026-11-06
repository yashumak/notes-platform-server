import { maskSensitiveData } from "./dataMasking.js";

const writeLog = (level, event, context) => {
  const output = JSON.stringify({
    level,
    event: maskSensitiveData(event),
    ...(context === undefined ? {} : { context: maskSensitiveData(context) }),
  });
  if (level === "error") {
    console.error(output);
  } else {
    console.log(output);
  }
};

export const logInfo = (event, context) => writeLog("info", event, context);
export const logError = (event, context) => writeLog("error", event, context);
