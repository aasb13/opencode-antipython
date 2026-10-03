import { Plugin } from "@opencode/plugin";
import { detect } from "./detect.js";
/**
 * tools whose command string we inspect, and the arg that holds it.
 *
 * NOTE: OpenCode V2 renamed the built-in `bash` tool to `shell`
 * (V1 permission action `bash` -> V2 `shell`). The tool id is `shell` in V2.
 */
const INSPECTED = {
    shell: "command",
    term_host_exec: "command",
    term_pty_exec: "command",
};
const VIA_LABEL = {
    "inline-c": "inline code via -c",
    "heredoc-stdin": "inline code via heredoc on stdin",
    "pipe-stdin": "inline code piped on stdin",
    "here-string": "inline code via here-string",
    "generated-script": "a python script generated in the same command",
    "in-place-sed": "an in-place sed replacement",
};
const PYTHON_GUIDANCE = [
    "Never write files with Python. Editing code through an interpreter garbles content,",
    "truncates files on failure, and bypasses the edit tool's diff tracking.",
    "Use the edit tool for surgical changes, the write tool for new or full-file content,",
    "and shell commands (cp, mv, rm, git checkout) for filesystem-level operations.",
    "Running real scripts and module invocations is still allowed: `python3 script.py`,",
    "`python3 -m pytest`, `uv run ...`.",
];
const SED_GUIDANCE = [
    "Never rewrite a file with `sed -i`. The rewritten content never appears as a diff",
    "you can check, a wrong delimiter or pattern silently leaves the file untouched or",
    "half-substituted, and the edit tool's change tracking is bypassed.",
    "Use the edit tool for surgical changes and the write tool for new or full-file content.",
    "Reading with sed is still allowed: `sed -n '1,20p' f`, `sed 's/x/y/' f | diff - f`.",
];
function message(tool, v) {
    const sed = v.via === "in-place-sed";
    return [
        sed
            ? `antipython: blocked - ${tool} would rewrite files with an in-place sed replacement (${v.reason}).`
            : `antipython: blocked - ${tool} would modify files through a Python interpreter (${v.reason}).`,
        "",
        `command: ${v.invocation.slice(0, 300)}`,
        `via:    ${VIA_LABEL[v.via] ?? v.via}`,
        `code:   ${v.excerpt}`,
        "",
        ...(sed ? SED_GUIDANCE : PYTHON_GUIDANCE),
    ].join("\n");
}
export const Antipython = Plugin.define({
    id: "antipython",
    async setup(ctx) {
        console.log(`antipython loaded for ${ctx.location.directory} (opencode ${ctx.app.version})`);
        await ctx.tool.hook("execute.before", (event) => {
            const argKey = INSPECTED[event.tool];
            if (!argKey)
                return;
            const command = event.input?.[argKey];
            if (typeof command !== "string" || command.length === 0)
                return;
            const violation = detect(command);
            if (!violation)
                return;
            console.log(`[antipython] blocked ${event.tool}: ${violation.reason} (via ${violation.via}) in session ${event.sessionID}`);
            throw new Error(message(event.tool, violation));
        });
    },
});
export default Antipython;
