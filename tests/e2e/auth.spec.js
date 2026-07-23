import { test, expect } from '@playwright/test';

test.describe.serial('Authentication Flow', () => {
  let page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
  });

  test.afterAll(async () => {
    await page.close();
  });

  test('should load the login page, verify setup/login states, and authenticate', async () => {
    // 1. Navigate to the login page
    await page.goto(`/index.html`);
    
    // 2. Check that the page title and branding are visible
    await expect(page).toHaveTitle(/Startup/i);
    await expect(page.locator('.brand-logo-container')).toBeVisible();

    // 3. Wait for the welcome animation to finish and one of the forms to become active
    await page.waitForSelector('[data-step="signin"].is-active, [data-step="setup"].is-active', { state: 'visible', timeout: 15000 });

    const isSetupVisible = await page.locator('[data-step="setup"].is-active').isVisible();
    const isSignInVisible = await page.locator('[data-step="signin"].is-active').isVisible();

    if (isSetupVisible) {
      // Test the Admin Setup flow
      console.log('Running Setup Admin flow...');
      await page.fill('#setup-name', 'Admin User');
      await page.fill('#setup-email', 'howardukah@startupbuild.tech');
      await page.fill('#setup-password', 'howard@2004ty');
      await page.fill('#setup-password2', 'howard@2004ty');
      await page.click('#btn-setup');

      // Should redirect to dashboard
      await expect(page).toHaveURL(/dashboard\.html/);
    } else if (isSignInVisible) {
      // Test the Login flow
      console.log('Running Sign-In flow...');
      await page.fill('#signin-user', 'howardukah@startupbuild.tech'); // assuming this exists
      await page.click('#btn-continue');
      
      await expect(page.locator('#signin-password-step')).toBeVisible({ timeout: 5000 });
      await page.fill('#signin-password', 'howard@2004ty');
      await page.click('#btn-signin');

      // Depending on if mustChangePassword is true, it might show newpw step
      // Wait a moment to see where we land
      await page.waitForTimeout(1000);
      const isNewPwVisible = await page.locator('[data-step="newpw"]').isVisible();
      if (isNewPwVisible) {
        await page.fill('#newpw-1', 'howard@2004ty4');
        await page.fill('#newpw-2', 'howard@2004ty4');
        await page.click('#btn-newpw');
      }

      // Should redirect to dashboard
      await expect(page).toHaveURL(/dashboard\.html/);
    }
  });

  test('should handle logout flow securely', async () => {
    // Wait for dashboard to load completely
    await expect(page.locator('.user-chip__logout')).toBeVisible({ timeout: 15000 });
    
    // Click logout
    await page.click('.user-chip__logout');

    // Verify logout typing animation text overlay
    const overlay = page.locator('#logout-overlay');
    await expect(overlay).toBeVisible();

    // Verify redirect back to index.html (animation takes ~2-3 seconds)
    await expect(page).toHaveURL(/index\.html/, { timeout: 10000 });
    
    // Verify we cannot go back to dashboard without logging in
    await page.goto(`/dashboard.html`);
    // The server/script should redirect us
    await expect(page).toHaveURL(/index\.html/);
  });

  test('should Auto Log Out if token is tampered/missing', async () => {
    // Go to login and authenticate again
    await page.goto(`/index.html`);
    await page.waitForSelector('[data-step="signin"].is-active', { state: 'visible', timeout: 5000 });
    await page.fill('#signin-user', 'howardukah@startupbuild.tech');
    await page.click('#btn-continue');
    
    await expect(page.locator('#signin-password-step')).toBeVisible({ timeout: 5000 });
    await page.fill('#signin-password', 'howard@2004ty');
    await page.click('#btn-signin');
    await expect(page).toHaveURL(/dashboard\.html/, { timeout: 10000 });

    // Tamper with token in both local and session storage
    await page.evaluate(() => {
      localStorage.setItem('crm-session-token', 'invalid_token');
      sessionStorage.setItem('crm-session-token', 'invalid_token');
    });

    // Refresh the page
    await page.reload();

    // Verify it boots us back to index.html
    await expect(page).toHaveURL(/index\.html/, { timeout: 5000 });
  });
});
