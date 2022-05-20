// complie 
// npx tsc
const testRpc = function(ctx: linna.Context, logger: linna.Logger, na: linna.Module, payload: string): string | void{
    logger.debug("Test Javascript RPC Call")
}

let InitModule: linna.InitModule =
        function(ctx: linna.Context, logger: linna.Logger, nk: linna.Module, initializer: linna.Initializer) {
    logger.info("Hello World!   -- js");

    initializer.registerRpc("testRpc", testRpc)
} 
