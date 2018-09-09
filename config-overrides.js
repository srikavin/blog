/* config-overrides.js */
const util = require('util');
module.exports = function override(config, env) {
    config.optimization.splitChunks.name = true;
    console.log(util.inspect(config, false, null, true /* enable colors */));
    // console.log(config);
    return config
};