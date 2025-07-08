import { chromium, type Browser, type LaunchOptions, type Page } from "playwright";
import { join } from "https://deno.land/std@0.224.0/path/mod.ts";

export class BrowserService {
    private static readonly DEFAULT_TIMEOUT = 30000;
    private static readonly LAUNCH_ARGS = [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-extensions'
    ];
    private static readonly PLAYWRIGHT_TEMP_DIR = join(Deno.cwd(), 'playwright-tmp');

    static async createBrowserInstance(): Promise<Browser> {

        await Deno.mkdir(BrowserService.PLAYWRIGHT_TEMP_DIR, { recursive: true });
        Deno.env.set('PLAYWRIGHT_TEMP_DIR', BrowserService.PLAYWRIGHT_TEMP_DIR);

        const launchConfig: LaunchOptions = {
            headless: true,
            args: this.LAUNCH_ARGS,
            timeout: this.DEFAULT_TIMEOUT
        };

        return await chromium.launch(launchConfig);
    }

    static async createNewPage(browser: Browser): Promise<Page> {
        const page = await browser.newPage();
        await page.setDefaultTimeout(this.DEFAULT_TIMEOUT);
        return page;
    }

    static async closeBrowserSafely(browser: Browser): Promise<void> {
        try {
            await browser.close();
        } catch (error) {
            console.warn('Failed to close browser gracefully:', error);
        }
    }
}
