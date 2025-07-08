import { BrowserService } from './browser.service.ts';
import { MutexLock } from '../utils/mutex.util.ts';
import type { SpotifyTokenData } from '../types/spotify.types.ts';
import type { Request, Response } from 'playwright';

export class SpotifyTokenService {
    private readonly tokenMutex = new MutexLock();
    private currentAccessToken: SpotifyTokenData | null = null;
    private refreshTimer: number | null = null;

    private static readonly SPOTIFY_OPEN_URL = 'https://open.spotify.com/';
    private static readonly TOKEN_ENDPOINT = '/api/token';
    private static readonly REFRESH_BUFFER_MS = 60000; // 1 minute before expiry
    private static readonly MIN_REFRESH_INTERVAL = 30000; // 30 seconds minimum
    private static readonly REQUEST_TIMEOUT = 30000;

    constructor() {
        this.initializeTokenService();
    }

    private async initializeTokenService(): Promise<void> {
        try {
            const initialToken = await this.fetchFreshToken();
            this.currentAccessToken = initialToken;
            this.scheduleTokenRefresh();
            console.log('Spotify token service initialized successfully');
        } catch (error) {
            console.error('Failed to initialize Spotify token service:', error);
        }
    }

    private scheduleTokenRefresh(): void {
        if (this.refreshTimer) {
            clearTimeout(this.refreshTimer);
        }

        if (!this.currentAccessToken) return;

        const currentTime = Date.now();
        const expirationTime = this.currentAccessToken.accessTokenExpirationTimestampMs;
        const timeUntilExpiry = expirationTime - currentTime;
        const refreshDelay = Math.max(
            timeUntilExpiry - SpotifyTokenService.REFRESH_BUFFER_MS,
            SpotifyTokenService.MIN_REFRESH_INTERVAL
        );

        this.refreshTimer = setTimeout(async () => {
            await this.performBackgroundRefresh();
            this.scheduleTokenRefresh();
        }, refreshDelay);

        console.log(`Next token refresh scheduled in ${Math.round(refreshDelay / 1000)}s`);
    }

    private async performBackgroundRefresh(): Promise<void> {
        try {
            const releaseCallback = await this.tokenMutex.acquireLock();
            try {
                const refreshedToken = await this.fetchFreshToken();
                this.currentAccessToken = refreshedToken;
                console.log('Token refreshed successfully in background');
            } finally {
                releaseCallback();
            }
        } catch (error) {
            console.error('Background token refresh failed:', error);
        }
    }

    private async fetchFreshToken(): Promise<SpotifyTokenData> {
        return new Promise<SpotifyTokenData>((resolve, reject) => {
            const timeoutId = setTimeout(() => {
                reject(new Error('Token fetch operation timed out'));
            }, SpotifyTokenService.REQUEST_TIMEOUT);

            this.executeBrowserTokenFetch()
                .then((tokenData) => {
                    clearTimeout(timeoutId);
                    resolve(tokenData);
                })
                .catch((error) => {
                    clearTimeout(timeoutId);
                    reject(error);
                });
        });
    }

    private async executeBrowserTokenFetch(): Promise<SpotifyTokenData> {
        const browser = await BrowserService.createBrowserInstance();
        const page = await BrowserService.createNewPage(browser);

        let tokenRequestProcessed = false;

        return new Promise<SpotifyTokenData>((resolve, reject) => {
            const cleanupAndReject = async (error: Error) => {
                page.removeAllListeners();
                await BrowserService.closeBrowserSafely(browser);
                reject(error);
            };

            const cleanupAndResolve = async (tokenData: SpotifyTokenData) => {
                page.removeAllListeners();
                await BrowserService.closeBrowserSafely(browser);
                resolve(tokenData);
            };

            page.on('requestfinished', async (request: Request) => {
                if (!request.url().includes(SpotifyTokenService.TOKEN_ENDPOINT)) return;

                tokenRequestProcessed = true;

                try {
                    const response: Response | null = await request.response();

                    if (!response || !response.ok()) {
                        await cleanupAndReject(new Error('Invalid response from Spotify API'));
                        return;
                    }

                    const responseData = await response.json();
                    const sanitizedData = this.sanitizeTokenData(responseData);

                    await cleanupAndResolve(sanitizedData);
                } catch (error) {
                    await cleanupAndReject(new Error(`Failed to process token response: ${error}`));
                }
            });

            page.goto(SpotifyTokenService.SPOTIFY_OPEN_URL).catch(async (error) => {
                if (!tokenRequestProcessed) {
                    await cleanupAndReject(new Error(`Failed to navigate to Spotify: ${error}`));
                }
            });
        });
    }

    private sanitizeTokenData(rawData: unknown): SpotifyTokenData {
        if (typeof rawData === 'object' && rawData !== null && '_notes' in rawData) {
            delete (rawData as Record<string, unknown>)._notes;
        }
        return rawData as SpotifyTokenData;
    }

    public async retrieveAccessToken(forceRefresh = false): Promise<SpotifyTokenData | null> {
        try {
            const cachedToken = this.currentAccessToken;
            const isTokenValid = cachedToken &&
                (cachedToken.accessTokenExpirationTimestampMs - 10000) > Date.now();

            if (!forceRefresh && isTokenValid) {
                return cachedToken;
            }

            const releaseCallback = await this.tokenMutex.acquireLock();
            try {
                const recentToken = this.currentAccessToken;
                const stillValidAfterWait = recentToken &&
                    (recentToken.accessTokenExpirationTimestampMs - 10000) > Date.now();

                if (!forceRefresh && stillValidAfterWait) {
                    return recentToken;
                }

                const freshToken = await this.fetchFreshToken();
                this.currentAccessToken = freshToken;
                return freshToken;
            } finally {
                releaseCallback();
            }
        } catch (error) {
            console.error('Token retrieval failed:', error);
            return null;
        }
    }

    public cleanup(): void {
        if (this.refreshTimer) {
            clearTimeout(this.refreshTimer);
            this.refreshTimer = null;
        }
    }
}
