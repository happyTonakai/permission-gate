/**
 * Auto-gofmt Extension
 *
 * After each agent turn, runs `gofmt -s -w` on any Go files that need it.
 * Keeps the working tree gofmt-clean so CI never trips on formatting.
 *
 * Why turn_end (not tool_execution_end):
 *   - One check per turn instead of per tool call.
 *   - Lets multi-edit turns settle before formatting.
 *
 * Why not git diff --name-only:
 *   - Untracked new .go files would be missed. Dry-running gofmt -l is
 *     cheaper and catches everything in the working tree.
 */

import { exec } from "node:child_process";
import { promisify } from "node:util";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const execAsync = promisify(exec);

export default function (pi: ExtensionAPI) {
	pi.on("turn_end", async (_event, ctx) => {
		try {
			const { stdout } = await execAsync("gofmt -s -l .", { cwd: process.cwd() });
			const files = stdout.trim().split("\n").filter(Boolean);
			if (files.length === 0) return;

			await execAsync(`gofmt -s -w ${files.map((f) => `"${f}"`).join(" ")}`, {
				cwd: process.cwd(),
			});

			if (ctx.hasUI) {
				ctx.ui.notify(`gofmt: reformatted ${files.length} file(s)`, "info");
			}
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			console.error(`[auto-gofmt] ${msg}`);
		}
	});
}
