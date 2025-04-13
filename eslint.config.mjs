// eslint.config.mjs
import config from "@carvajalconsultants/eslint-config";
import globals from "globals";

for (const key of Object.keys(globals.browser)) {
  if (key !== key.trim()) {
    console.log(`Global with whitespace: "${key}"`);
  }
}

export default [...config];
