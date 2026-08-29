import { defineConfig, devices } from '@playwright/test';
import dotenv from 'dotenv';

dotenv.config({ path: '.env.e2e.local', quiet: true });

export default defineConfig({
  testDir: './e2e',
  outputDir: 'runtime-evidence/browser/test-results',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'runtime-evidence/browser/report', open: 'never' }],
  ],
  use: {
    baseURL: process.env.WAM_E2E_URL || 'https://192.168.56.21',
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 1000 },
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    video: 'retain-on-failure',
    actionTimeout: 10_000,
    navigationTimeout: 60_000,
  },
  projects: [
    {
      name: 'desktop-chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
