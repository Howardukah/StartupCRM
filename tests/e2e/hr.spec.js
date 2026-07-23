import { test, expect } from '@playwright/test';

test.describe.serial('HR: Time Tracking & Payroll', () => {
  let page;

  test.beforeAll(async ({ browser }) => {
    test.setTimeout(120000);
    page = await browser.newPage();
    
    // Set fixed time to 12:00 PM on a random future day to ensure clock-in is open and fresh
    const daysOffset = Math.floor(Math.random() * 10000);
    const testDate = new Date(Date.UTC(2030, 0, 1 + daysOffset, 12, 0, 0));
    await page.clock.setFixedTime(testDate);

    // Login as Admin
    await page.goto('/index.html');
    await page.waitForSelector('[data-step="signin"].is-active', { state: 'visible', timeout: 5000 });
    await page.fill('#signin-user', 'howardukah@startupbuild.tech');
    await page.click('#btn-continue');
    
    await expect(page.locator('#signin-password-step')).toBeVisible({ timeout: 5000 });
    await page.fill('#signin-password', 'howard@2004ty');
    await page.click('#btn-signin');
    await expect(page).toHaveURL(/dashboard\.html/, { timeout: 10000 });

    // Hide modals that might intercept clicks
    await page.addStyleTag({ content: '#privacy-notice-dialog, #modal-deadline-alert { display: none !important; pointer-events: none !important; }' });
  });

  test.afterAll(async () => {
    await page.close();
  });

  test('should clock in from overview page', async () => {
    // The deadline alert pops up asynchronously after projects load (since we moved the clock to 2030)
    // We'll hide it via CSS so it never intercepts clicks
    await page.addStyleTag({ content: '#modal-deadline-alert { display: none !important; pointer-events: none !important; }' });
    
    await page.click('a[data-nav="overview"]');
    await expect(page.locator('[data-section="overview"]')).toBeVisible();

    const clockInBtn = page.locator('button:has-text("Clock-in")');
    await expect(clockInBtn).toBeEnabled();
    await clockInBtn.click();

    // Verify Toast
    await expect(page.locator('.toast').filter({ hasText: /Clocked in/i })).toBeVisible({ timeout: 10000 });

    // Verify timer appears
    await expect(page.locator('#ov-clock-timer')).toBeVisible();
    await expect(page.locator('button:has-text("Break")')).toBeVisible();
  });

  test('should take a break and resume', async () => {
    // Start break
    await page.click('button:has-text("Break")');
    await expect(page.locator('.toast').filter({ hasText: /Break started/i })).toBeVisible({ timeout: 10000 });

    // Verify resume button appears
    const resumeBtn = page.locator('button:has-text("Resume")');
    await expect(resumeBtn).toBeVisible();

    // End break
    await resumeBtn.click();
    // No specific toast for resuming break, but button should change back to Break
    await expect(page.locator('button:has-text("Break")')).toBeVisible();
  });

  test('should clock out', async () => {
    await page.click('button:has-text("Clock-out")');
    await expect(page.locator('.toast').filter({ hasText: /Clocked out/i })).toBeVisible({ timeout: 10000 });

    // Timer should disappear or go back to state showing it's closed
    await expect(page.locator('button:has-text("Clock-out")')).not.toBeVisible();
  });

  test('should view payroll table', async () => {
    await page.click('a[data-nav="payroll"]');
    await expect(page.locator('[data-section="payroll"]')).toBeVisible();

    // Refresh payroll just in case
    await page.click('[data-section="payroll"] button:has-text("Refresh")');

    // Admin should appear in the table
    const row = page.locator('#payroll-tbody tr').filter({ hasText: 'Howard Ukah' });
    await expect(row).toBeVisible();

    // Verify some values exist in the row
    await expect(row.locator('td').nth(1)).toContainText(/hrs?\/day/); // Opted hours
  });
});
