/* config-overrides.js */
module.exports = function override(config, env) {
    config.optimization.splitChunks.name = true;
    return config
};