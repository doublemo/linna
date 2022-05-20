"use strict";
// complie 
// npx tsc
var testRpc = function (ctx, logger, na, payload) {
    logger.debug("Test Javascript RPC Call");
};
var InitModule = function (ctx, logger, nk, initializer) {
    logger.info("Hello World!   -- js");
    initializer.registerRpc("testRpc", testRpc);
};
