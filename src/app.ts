import { Hono } from 'hono'
import { SpotifyTokenService } from "./services/spotify-token.service.ts";
import { TokenController } from "./controllers/token.controller.ts";

const spotifyTokenService = new SpotifyTokenService();
const tokenController = new TokenController(spotifyTokenService);

const app = new Hono();

app.get('/api/token', async (c) => {
    const result = await tokenController.handleTokenRequest(c);
    return c.json(result);
});
app.get('/health', (c) => {
    return c.json({
        status: 'healthy',
        timestamp: Date.now(),
        version: '1.0.0',
        message: 'Server is running smoothly'
    });
});

Deno.serve(app.fetch);
