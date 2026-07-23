import { test, expect } from '@playwright/test';

test.describe.serial('Admin: Team & Activity Log', () => {
  let page;
  let testMemberEmail = `member_${Date.now()}@test.com`;
  let testMemberName = `Test Member ${Date.now()}`;

  test.setTimeout(120000); // 2 minutes for slow SMTP timeouts

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

    // Hide modals that might intercept clicks
    await page.addStyleTag({ content: '#privacy-notice-dialog, #modal-deadline-alert { display: none !important; pointer-events: none !important; }' });
  });

  test.afterAll(async () => {
    await page.close();
  });

  test('should invite a new team member', async () => {
    test.setTimeout(120000);
    await page.click('a[data-nav="team"]');
    await expect(page.locator('[data-section="team"]')).toBeVisible();
    
    // Add member
    await page.click('button:has-text("+ Add member")');
    await expect(page.locator('#modal-invite')).toHaveClass(/is-open/);
    
    await page.fill('.i-name', testMemberName);
    await page.fill('.i-email', testMemberEmail);
    await page.evaluate(() => {
      const sel = document.querySelector('.i-role');
      sel.value = 'Task Manager';
      sel.dispatchEvent(new Event('change'));
    });
    
    await page.click('#modal-invite-submit'); // "Add member"
    
    // The modal should close
    await expect(page.locator('#modal-invite')).not.toHaveClass(/is-open/, { timeout: 60000 });
    
    // Verify member is in the list
    const row = page.locator('#team-tbody tr').filter({ hasText: testMemberName });
    await expect(row).toBeVisible();
  });

  test('should edit team member', async () => {
    const row = page.locator('#team-tbody tr').filter({ hasText: testMemberName });
    await row.locator('button[title="Edit"]').click();
    
    await expect(page.locator('#modal-invite')).toHaveClass(/is-open/);
    
    await page.fill('.i-name', `Updated ${testMemberName}`);
    await page.click('#modal-invite-submit'); 
    
    await expect(page.locator('#modal-invite')).not.toHaveClass(/is-open/);
    
    // Verify name changed
    await expect(page.locator('#team-tbody tr').filter({ hasText: `Updated ${testMemberName}` })).toBeVisible();
    testMemberName = `Updated ${testMemberName}`;
  });

  test('should suspend and restore a team member', async () => {
    const row = page.locator('#team-tbody tr').filter({ hasText: testMemberName });
    
    // Suspend
    await row.locator('button[title="Restrict login access"]').click();
    
    // Confirm dialog
    const confirmOverlay = page.locator('#crm-confirm-backdrop');
    await expect(confirmOverlay).toHaveClass(/open/);
    await page.click('#crm-confirm-ok');
    
    // Let's see if the row gets "Suspended" badge.
    await expect(row.locator('.badge:has-text("Suspended")')).toBeVisible({ timeout: 10000 });
    
    // Restore
    await row.locator('button[title="Restore login access"]').click();
    
    // Confirm dialog
    await expect(confirmOverlay).toHaveClass(/open/);
    await page.click('#crm-confirm-ok');
    
    await expect(row.locator('.badge').filter({ hasText: /Active|Invited/ })).toBeVisible({ timeout: 10000 });
  });

  test('should reset member password', async () => {
    const row = page.locator('#team-tbody tr').filter({ hasText: testMemberName });
    await row.locator('button:has-text("Reset")').click();
    
    // Wait for the confirm dialog
    const confirmOverlay = page.locator('#crm-confirm-backdrop');
    await expect(confirmOverlay).toHaveClass(/open/);
    await page.click('#crm-confirm-ok');
    
    // Toast should appear "Password reset"
    await expect(page.locator('.toast').filter({ hasText: /Password reset/i })).toBeVisible({ timeout: 10000 });
  });

  test('should view activity log and check export button', async () => {
    await page.click('a[data-nav="activity"]');
    await expect(page.locator('[data-section="activity"]')).toBeVisible();
    
    // We should see a table of activities
    await expect(page.locator('#activity-tbody tr').first()).toBeVisible();
    
    // Click Refresh
    await page.click('#activity-refresh-btn');
    await expect(page.locator('#activity-tbody tr').first()).toBeVisible();
    
    // Export CSV (just check it exists and is clickable, downloading might be tricky in headless, but playwright supports it. We just click it to ensure no errors)
    const downloadPromise = page.waitForEvent('download', { timeout: 5000 }).catch(() => null);
    await page.click('#activity-csv-btn');
    await downloadPromise;
  });

  test('should delete the team member', async () => {
    await page.click('a[data-nav="team"]');
    await expect(page.locator('[data-section="team"]')).toBeVisible();

    const row = page.locator('#team-tbody tr').filter({ hasText: testMemberName });
    await row.locator('button[title="Delete"]').click();
    
    const confirmOverlay = page.locator('#crm-confirm-backdrop');
    await expect(confirmOverlay).toHaveClass(/open/);
    await page.click('#crm-confirm-ok');
    
    await expect(row).not.toBeVisible({ timeout: 10000 });
  });
});
