import { detect } from "./detect.js";
/** tools whose command string we inspect, and the arg that holds it */
const INSPECTED = {
    bash: "command",
    term_host_exec: "command",
    term_pty_exec: "command",
};
const VIA_LABEL = {
    "inline-c": "inline code via -c",
    "heredoc-stdin": "inline code via heredoc on stdin",
    "pipe-stdin": "inline code piped on stdin",
    "here-string": "inline code via here-string",
    "generated-script": "a python script generated in the same command",
};
function message(tool, v) {
    return [
        `antipython: blocked - ${tool} would modify files through a Python interpreter (${v.reason}).`,
        "",
        `command: ${v.invocation.slice(0, 300)}`,
        `via:    ${VIA_LABEL[v.via] ?? v.via}`,
        `code:   ${v.excerpt}`,
        "",
        "Never write files with Python. Editing code through an interpreter garbles content,",
        "truncates files on failure, and bypasses the edit tool's diff tracking.",
        "Use the edit tool for surgical changes, the write tool for new or full-file content,",
        "and shell commands (sed, tee, cp, rm) for filesystem-level operations.",
        "Running real scripts and module invocations is still allowed: `python3 script.py`,",
        "`python3 -m pytest`, `uv run ...`.",
    ].join("\n");
}
export const Antipython = async ({ client }) => {
    return {
        "tool.execute.before": async (input, output) => {
            const argKey = INSPECTED[input.tool];
            if (!argKey)
                return;
            const command = output.args?.[argKey];
            if (typeof command !== "string" || command.length === 0)
                return;
            const violation = detect(command);
            if (!violation)
                return;
            void client?.app
                ?.log?.({
                body: {
                    service: "antipython",
                    level: "warn",
                    message: `blocked ${input.tool}: ${violation.reason}`,
                    extra: { tool: input.tool, via: violation.via, invocation: violation.invocation },
                },
            })
                .catch?.(() => { });
            throw new Error(message(input.tool, violation));
        },
    };
};
export default Antipython;
