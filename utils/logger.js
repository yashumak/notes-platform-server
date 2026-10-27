const writeLog = (level, event) => {
  const output = JSON.stringify({ level, event });
  if (level === "error") {
    console.error(output);
  } else {
    console.log(output);
  }
};

export const logInfo = (event) => writeLog("info", event);
export const logError = (event) => writeLog("error", event);
