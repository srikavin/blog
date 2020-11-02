const HTMLAsset = require('parcel-bundler/lib/assets/HTMLAsset')

function shouldIgnore(file) {
    return /\/$/.test(file)
}

class SkipIndexHtml extends HTMLAsset {
    addDependency(name, opts) {
        return undefined;
        if (!shouldIgnore(opts.resolved)) {
            return super.addDependency(name, opts)
        }
    }

    processSingleDependency(p, opts) {
        return p;
    }
}

module.exports = SkipIndexHtml
