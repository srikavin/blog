var childProcess = require('child_process');

try {
    if (process.platform === 'win32') {
        childProcess.execFileSync("bin/zola.exe", process.argv.slice(2), {stdio: "inherit"})
    } else {
        childProcess.execFileSync("bin/zola", process.argv.slice(2), {stdio: "inherit"})
    }
} catch (e) {

}

