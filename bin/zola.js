import * as childProcess from 'child_process';
import {fileURLToPath} from "url";

export const runZola = function (args) {
    if (process.platform === 'win32') {
        childProcess.execFileSync("bin/zola.exe", args, {stdio: "inherit"})
    } else {
        childProcess.execFileSync("bin/zola", args, {stdio: "inherit"})
    }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    runZola(process.argv.slice(2));
}
