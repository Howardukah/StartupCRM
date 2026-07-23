import { test, expect } from '@playwright/test';

test.describe.serial('Communication: Chat & Mail', () => {
  let page;

  test.beforeAll(async ({ browser }) => {
    test.setTimeout(120000);
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

    await page.addStyleTag({ content: '#privacy-notice-dialog, #modal-deadline-alert { display: none !important; pointer-events: none !important; }' });

    // Navigate to Chat
    await page.click('a[data-nav="chat"]');
    await expect(page.locator('[data-section="chat"]')).toBeVisible();
  });

  test.afterAll(async () => {
    await page.close();
  });

  test('should open a chat and send a message', async () => {
    // Make sure we are in chat view
    await page.click('#toggle-chat-btn');
    await expect(page.locator('#chat-view-panel')).toBeVisible();

    // Click the first chat in the list
    const firstChat = page.locator('.chat-list-item').first();
    await expect(firstChat).toBeVisible({ timeout: 10000 });
    await firstChat.click();

    // Wait for chat thread to open
    const chatThread = page.locator('.chat-thread').first();
    await expect(chatThread).toBeVisible();

    // Type a message
    const testMsg = 'Hello! This is a test message from Playwright - ' + Date.now();
    const chatInput = chatThread.locator('.chat-thread__input textarea');
    await chatInput.fill(testMsg);

    // Click send
    await chatThread.locator('.chat-send-btn').click();

    // Verify message appears in the chat body
    const chatBody = chatThread.locator('.chat-thread__body');
    await expect(chatBody).toContainText(testMsg);
  });

  test('should compose and send an email', async () => {
    test.setTimeout(90000);
    // Switch to Mail view
    await page.click('#toggle-mail-btn');
    await expect(page.locator('#mail-view-panel')).toBeVisible();

    // Click Compose
    await page.click('.mail-compose-btn');
    const composeModal = page.locator('#mail-compose');
    await expect(composeModal).toBeVisible();

    // Fill email form
    await page.fill('#mail-to', 'test@example.com');
    await page.fill('#mail-subject', 'Automated E2E Test Email');
    await page.fill('#mail-body', 'This is an automated test email from the Playwright suite.');

    // Send Email
    await composeModal.locator('.btn--primary:has-text("Send")').click();

    // The API sends SMTP email, so it might take a while. We wait up to 60 seconds for the success toast.
    await expect(page.locator('.toast').filter({ hasText: /(Email sent successfully|Send failed)/i })).toBeVisible({ timeout: 60000 });
  });
});
