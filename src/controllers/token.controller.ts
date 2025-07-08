import { Context } from "hono";
import type { SpotifyTokenService } from '../services/spotify-token.service.ts';

export class TokenController {
    constructor(private readonly tokenService: SpotifyTokenService) { }

    async handleTokenRequest(
        ctx: Context,
    ): Promise<Response> {
        const queryParams = ctx.req.query();
        const shouldForceRefresh = this.parseForceParameter(queryParams.force);

        try {
            const tokenData = await this.tokenService.retrieveAccessToken(shouldForceRefresh);

            if (!tokenData) {
                return ctx.json({
                    error: 'Token service temporarily unavailable',
                }, 503);
            }

            return ctx.json(tokenData, 200);
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
            return ctx.json({
                success: false,
                error: errorMessage
            }, 500);
        }
    }

    private parseForceParameter(forceParam?: string): boolean {
        if (!forceParam) return false;

        const truthy = ["1", "yes", "true", "on"];
        return truthy.includes(forceParam.toLowerCase());
    }
}
