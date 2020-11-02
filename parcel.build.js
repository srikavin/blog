const Bundler = require('parcel-bundler')
const path = require('path')

const entryFiles = ['public/*.html', 'public/**/*.html']

const options = {
    outdir: './dist',
    outFile: 'index.html',
    publicUrl: '/',
    cache: false,
    cacheDir: '.cache',
    minify: true,
    target: 'browser',
    sourceMaps: true,
    detailedReport: true,
}

// Initializes a bundler using the entrypoint location and options provided
const bundler = new Bundler(entryFiles, options);

bundler.addAssetType('html', require.resolve('./parcel.html.js'))

// Run the bundler, this returns the main bundle
// Use the events if you're using watch mode as this promise will only trigger once and not for every rebuild
bundler.bundle();
