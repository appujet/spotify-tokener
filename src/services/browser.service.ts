import { chromium, type Browser, type LaunchOptions, type Page } from "playwright";

export class BrowserService {
    private static readonly DEFAULT_TIMEOUT = 30000;
    private static readonly LAUNCH_ARGS = [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-extensions'
    ];

    static async createBrowserInstance(): Promise<Browser> {
        const customExecutablePath = Bun.env.BROWSER_PATH?.trim();

        const launchConfig: LaunchOptions = {
            headless: true,
            args: this.LAUNCH_ARGS,
            timeout: this.DEFAULT_TIMEOUT
        };

        if (customExecutablePath) {
            launchConfig.executablePath = customExecutablePath;
        }

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
  