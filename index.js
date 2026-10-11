// OpenCode V2 plugin entrypoint.
//
// V2 resolves a plugin directory's entrypoint from the directory ROOT
// (`<dir>/index.js`). It does NOT read the `main` field in package.json --
// with `main: "./dist/index.js"` the plugin was silently skipped with no error
// in the logs. This root file is what makes it load, so keep it.
export { default, Antipython } from "./dist/index.js"
