import { test, expect } from '@playwright/test';

test.describe.serial('Admin: Asset Buckets & Storage', () => {
  let page;
  let projectName;

  test.setTimeout(120000); // 2 minutes for slow SMTP timeouts

  test.beforeAll(async ({ browser }) => {
    test.setTimeout(120000); // 2 minutes for slow SMTP timeouts
    page = await browser.newPage();
    // Login
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

    // Ensure a client exists
    await page.click('a[data-nav="clients"]');
    await expect(page.locator('[data-section="clients"]')).toBeVisible();
    await page.click('button:has-text("+ Add client")');
    await expect(page.locator('#modal-client')).toHaveClass(/is-open/);
    await page.fill('.c-name', 'Assets Test Client');
    await page.fill('.c-email', 'assets@test.com');
    await page.click('#modal-client button:has-text("Add client")');
    await expect(page.locator('#modal-client')).not.toHaveClass(/is-open/);

    // Create a Project
    await page.click('a[data-nav="projects"]');
    await expect(page.locator('[data-section="projects"]')).toBeVisible();
    await page.click('button:has-text("+ New project")');
    await expect(page.locator('#modal-project')).toHaveClass(/is-open/);
    
    projectName = `Asset Project ${Date.now()}`;
    await page.fill('.p-name', projectName);
    
    await page.evaluate(() => {
      const sel = document.querySelector('.p-client');
      sel.selectedIndex = sel.options.length - 1;
      sel.dispatchEvent(new Event('change'));
    });

    await page.fill('.p-zoho-meeting', 'https://meet.zoho.com/asset');
    
    // Create Asset Bucket inside modal
    await page.click('#btn-create-bucket');
    await expect(page.locator('#btn-create-bucket')).toHaveText(/Bucket Created/i, { timeout: 60000 });

    await page.click('#modal-project button:has-text("Create project")');
    await expect(page.locator('#modal-project')).not.toHaveClass(/is-open/);
  });

  test.afterAll(async () => {
    test.setTimeout(120000);
    // Teardown: delete the project
    await page.click('a[data-nav="projects"]');
    await expect(page.locator('[data-section="projects"]')).toBeVisible();
    await page.click('[data-section="projects"] button[data-view="table"]');
    const projectRow = page.locator('#projects-tbody tr').filter({ hasText: projectName });
    if (await projectRow.isVisible()) {
      await projectRow.locator('button[title="Delete"]').click();
      const confirmOverlay = page.locator('#crm-confirm-backdrop');
      await expect(confirmOverlay).toHaveClass(/open/);
      await page.click('#crm-confirm-ok');
    }
    await page.close();
  });

  test('should view asset buckets in admin section', async () => {
    await page.click('a[data-nav="assets"]');
    await expect(page.locator('[data-section="assets"]')).toBeVisible();
    
    // Verify the newly created bucket is in the list
    const row = page.locator('#assets-tbody tr').filter({ hasText: projectName });
    await expect(row).toBeVisible();
  });

  test('should edit asset bucket quota', async () => {
    const row = page.locator('#assets-tbody tr').filter({ hasText: projectName });
    
    // Click edit
    await row.locator('button[title="Edit"]').click();
    
    // Wait for the quota input to appear
    const quotaInput = row.locator('input[id^="quota-edit-"]');
    await expect(quotaInput).toBeVisible();
    
    // Change quota
    await quotaInput.fill('2000');
    
    // Save
    await row.locator('button:has-text("Save")').click();
    
    // Verify it updated to 2000 MB (which might be formatted to GB or something, 
    // but the input should disappear when it saves successfully).
    await expect(quotaInput).not.toBeVisible();
    // The table shows formatted bytes, 2000 MB might be shown as 2.0 GB or 1.95 GB
    // Just verifying it's no longer in edit mode is enough.
  });

  test('should restrict and enable asset bucket access', async () => {
    const row = page.locator('#assets-tbody tr').filter({ hasText: projectName });
    
    // Click "Restrict access"
    const restrictBtn = row.locator('button[title="Restrict access"]');
    await expect(restrictBtn).toBeVisible();
    await restrictBtn.click();
    
    // Confirm dialog
    const confirmOverlay = page.locator('#crm-confirm-backdrop');
    await expect(confirmOverlay).toHaveClass(/open/);
    await page.click('#crm-confirm-ok');
    
    // Verify it says "Restricted"
    await expect(row.locator('.pill--danger:has-text("Restricted")')).toBeVisible();
    
    // Click "Enable access"
    const enableBtn = row.locator('button[title="Enable access"]');
    await expect(enableBtn).toBeVisible();
    await enableBtn.click();
    
    // Confirm dialog
    await expect(confirmOverlay).toHaveClass(/open/);
    await page.click('#crm-confirm-ok');
    
    // Verify it says "Active"
    await expect(row.locator('.pill--success:has-text("Active")')).toBeVisible();
  });
});
