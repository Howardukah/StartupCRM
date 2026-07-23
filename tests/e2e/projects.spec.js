import { test, expect } from '@playwright/test';

test.describe.serial('Project Management', () => {
  let page;
  let projectName;

  test.beforeAll(async ({ browser }) => {
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

    // Hide modals that might intercept clicks
    await page.addStyleTag({ content: '#privacy-notice-dialog, #modal-deadline-alert { display: none !important; pointer-events: none !important; }' });

    // Prerequisite: Create a client so we can create a project
    await page.click('a[data-nav="clients"]');
    await expect(page.locator('[data-section="clients"]')).toBeVisible();
    await page.click('button:has-text("+ Add client")');
    await expect(page.locator('#modal-client')).toHaveClass(/is-open/);
    await page.fill('.c-name', 'E2E Client');
    await page.fill('.c-company', 'Test Company LLC');
    await page.fill('.c-email', 'client@test.com');
    await page.click('#modal-client button:has-text("Add client")');
    await expect(page.locator('#modal-client')).not.toHaveClass(/is-open/);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test('should create a new project', async () => {
    // Navigate to projects section
    await page.click('a[data-nav="projects"]');
    await expect(page.locator('[data-section="projects"]')).toBeVisible();

    // Click + New project
    await page.click('button:has-text("+ New project")');
    await expect(page.locator('#modal-project')).toHaveClass(/is-open/);

    // Fill form
    projectName = `E2E Project ${Date.now()}`;
    await page.fill('.p-name', projectName);
    
    // Select the newly created client
    const clientSelect = page.locator('.p-client');
    // The native select is hidden, so we use page.evaluate instead of selectOption
    // Wait, the option label might be different. Let's select the last option
    await page.evaluate(() => {
      const sel = document.querySelector('.p-client');
      sel.selectedIndex = sel.options.length - 1; // pick the last client
      sel.dispatchEvent(new Event('change'));
    });

    await page.fill('.p-preview-url', 'https://github.com/test');
    await page.fill('.p-zoho-meeting', 'https://meet.zoho.com/test');

    // Submit
    await page.click('#modal-project button:has-text("Create project")');
    
    // Verify modal closes
    await expect(page.locator('#modal-project')).not.toHaveClass(/is-open/);

    // Verify project appears in the project list (Kanban view by default)
    await expect(page.locator(`.kanban__card-title:has-text("${projectName}")`)).toBeVisible();
  });

  test('should edit a project', async () => {
    await page.click('a[data-nav="projects"]');
    await expect(page.locator('[data-section="projects"]')).toBeVisible();

    // Switch to table view to see edit/delete buttons
    await page.click('[data-section="projects"] button[data-view="table"]');

    const projectRow = page.locator('#projects-tbody tr').filter({ hasText: projectName });

    // Click edit
    await projectRow.locator('button[title="Edit"]').click();
    await expect(page.locator('#modal-project')).toHaveClass(/is-open/);

    // Change name
    const newName = `${projectName} - Edited`;
    await page.fill('.p-name', newName);
    await page.click('#modal-project button:has-text("Create project")');

    // Wait for save
    await expect(page.locator('#modal-project')).not.toHaveClass(/is-open/);
    
    // Verify name changed in the table
    await expect(page.locator(`#projects-tbody td.tbl__name:has-text("${newName}")`)).toBeVisible();
    projectName = newName;
  });

  test('should delete a project', async () => {
    await page.click('a[data-nav="projects"]');
    await expect(page.locator('[data-section="projects"]')).toBeVisible();

    // Switch to table view
    await page.click('[data-section="projects"] button[data-view="table"]');

    const projectRow = page.locator('#projects-tbody tr').filter({ hasText: projectName });

    // Click delete
    await projectRow.locator('button[title="Delete"]').click();

    // Confirm modal opens
    const confirmOverlay = page.locator('#crm-confirm-backdrop');
    await expect(confirmOverlay).toHaveClass(/open/);
    await page.click('#crm-confirm-ok');

    // Wait for it to disappear
    await expect(projectRow).not.toBeVisible();
  });
});
