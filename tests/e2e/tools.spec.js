import { test, expect } from '@playwright/test';

test.describe.serial('Productivity Tools: Spreadsheets & Notes', () => {
  let page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    
    // Login as Admin
    await page.goto('/index.html');
    await page.waitForSelector('[data-step="signin"].is-active', { state: 'visible', timeout: 5000 });
    await page.fill('#signin-user', 'howardukah@startupbuild.tech');
    await page.click('#btn-continue');
    
    await expect(page.locator('#signin-password-step')).toBeVisible({ timeout: 5000 });
    await page.fill('#signin-password', 'howard@2004ty');
    await page.click('#btn-signin');
    await expect(page).toHaveURL(/dashboard\.html/, { timeout: 10000 });

    // Hide pesky modals that might pop up
    await page.addStyleTag({ content: '#privacy-notice-dialog, #modal-deadline-alert { display: none !important; pointer-events: none !important; }' });
  });

  test.afterAll(async () => {
    await page.close();
  });

  test('should create and rename a spreadsheet', async () => {
    await page.click('a[data-nav="spreadsheets"]');
    await expect(page.locator('[data-section="spreadsheets"]')).toBeVisible();

    // Click New Spreadsheet
    await page.click('button:has-text("New Spreadsheet")');
    
    // Editor should be visible
    const editor = page.locator('#ss-editor');
    await expect(editor).toBeVisible();

    // Type a title
    const titleInput = page.locator('#ss-title-input');
    const testTitle = 'E2E Test Spreadsheet - ' + Date.now();
    await titleInput.fill(testTitle);
    await titleInput.blur(); // Trigger onchange if needed

    // Verify it appears in the list
    await expect(page.locator('#ss-list').filter({ hasText: testTitle })).toBeVisible({ timeout: 5000 });
  });

  test('should create a note', async () => {
    await page.click('a[data-nav="notes"]');
    await expect(page.locator('[data-section="notes"]')).toBeVisible();

    // Click New Note
    await page.click('button:has-text("New Note")');
    
    // Editor should be visible
    const editor = page.locator('#note-editor');
    await expect(editor).not.toHaveClass(/hidden/);
    
    // Type a title
    const titleInput = page.locator('#note-title-input');
    const testTitle = 'E2E Test Note - ' + Date.now();
    await titleInput.fill(testTitle);
    
    // Type body
    const bodyInput = page.locator('#note-body-input');
    await bodyInput.fill('This is a test note created by Playwright.');

    // Verify it appears in the list
    await expect(page.locator('#notes-list').filter({ hasText: testTitle })).toBeVisible({ timeout: 5000 });
  });
});
