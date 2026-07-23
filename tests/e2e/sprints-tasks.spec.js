import { test, expect } from '@playwright/test';

test.describe.serial('Sprints and Tasks', () => {
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

    // Ensure a client exists
    await page.click('a[data-nav="clients"]');
    await expect(page.locator('[data-section="clients"]')).toBeVisible();
    await page.click('button:has-text("+ Add client")');
    await expect(page.locator('#modal-client')).toHaveClass(/is-open/);
    await page.fill('.c-name', 'Sprint Test Client');
    await page.fill('.c-email', 'sprint@test.com');
    await page.click('#modal-client button:has-text("Add client")');
    await expect(page.locator('#modal-client')).not.toHaveClass(/is-open/);

    // Create a Project
    await page.click('a[data-nav="projects"]');
    await expect(page.locator('[data-section="projects"]')).toBeVisible();
    await page.click('button:has-text("+ New project")');
    await expect(page.locator('#modal-project')).toHaveClass(/is-open/);
    
    projectName = `Sprint E2E ${Date.now()}`;
    await page.fill('.p-name', projectName);
    
    await page.evaluate(() => {
      const sel = document.querySelector('.p-client');
      sel.selectedIndex = sel.options.length - 1;
      sel.dispatchEvent(new Event('change'));
    });

    await page.fill('.p-zoho-meeting', 'https://meet.zoho.com/sprint');
    await page.click('#modal-project button:has-text("Create project")');
    await expect(page.locator('#modal-project')).not.toHaveClass(/is-open/);
    await expect(page.locator(`.kanban__card-title:has-text("${projectName}")`)).toBeVisible();
  });

  test.afterAll(async () => {
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

  test('should open project detail and create a sprint manually', async () => {
    await page.click('a[data-nav="projects"]');
    await expect(page.locator('[data-section="projects"]')).toBeVisible();
    await page.click('button[data-view="kanban"]');
    await page.click(`.kanban__card-title:has-text("${projectName}")`);
    
    // Project detail view should open
    await expect(page.locator('#project-detail')).toBeVisible();

    // Click + New sprint
    await page.click('button:has-text("+ New sprint")');
    await expect(page.locator('#modal-sprint')).toHaveClass(/is-open/);

    await page.fill('.s-name', 'Manual Sprint 1');
    await page.fill('.s-range', 'Jul 15 - Jul 22');
    await page.click('#modal-sprint button:has-text("Create sprint")');
    
    await expect(page.locator('#modal-sprint')).not.toHaveClass(/is-open/);
    
    // Verify sprint created
    await expect(page.locator('details summary:has-text("Manual Sprint 1")')).toBeVisible();
  });

  test('should create a task in the sprint', async () => {
    const sprintDetails = page.locator('details').filter({ hasText: 'Manual Sprint 1' });
    
    await sprintDetails.locator('button:has-text("+ Add task")').click();
    
    await expect(page.locator('#modal-task')).toHaveClass(/is-open/);
    
    await page.fill('.t-title', 'Implement Login Feature');
    await page.click('#modal-task button:has-text("Add task")');
    
    await expect(page.locator('#modal-task')).not.toHaveClass(/is-open/);

    // Verify task is visible
    await expect(sprintDetails.locator('.sprint-task:has-text("Implement Login Feature")')).toBeVisible();
  });

  test('should edit a task', async () => {
    const sprintDetails = page.locator('details').filter({ hasText: 'Manual Sprint 1' });
    const taskEl = sprintDetails.locator('.sprint-task:has-text("Implement Login Feature")');
    
    // Click edit button
    await taskEl.locator('button[title="Edit task"]').click();
    await expect(page.locator('#modal-task')).toHaveClass(/is-open/);
    
    await page.fill('.t-title', 'Implement Login Feature v2');
    await page.click('#modal-task button:has-text("Save task")');
    
    await expect(page.locator('#modal-task')).not.toHaveClass(/is-open/);
    
    await expect(sprintDetails.locator('.sprint-task:has-text("Implement Login Feature v2")')).toBeVisible();
  });

  test('should toggle task status', async () => {
    const sprintDetails = page.locator('details').filter({ hasText: 'Manual Sprint 1' });
    const taskEl = sprintDetails.locator('.sprint-task:has-text("Implement Login Feature v2")');
    
    // Check if it has 'Todo' badge
    await expect(taskEl.locator('.badge:has-text("Todo")')).toBeVisible();
    
    // Click checkmark
    await taskEl.locator('.sprint-task__check').click();
    
    // Check if it has 'Done' badge
    await expect(taskEl.locator('.badge:has-text("Done")')).toBeVisible();
  });

  test('should change sprint status', async () => {
    const sprintDetails = page.locator('details').filter({ hasText: 'Manual Sprint 1' });
    const select = sprintDetails.locator('.sprint-status-select');
    
    // Select customer-review
    await select.selectOption({ value: 'customer-review' });
    await expect(select).toHaveValue('customer-review');
  });

  test('should delete a task', async () => {
    const sprintDetails = page.locator('details').filter({ hasText: 'Manual Sprint 1' });
    const taskEl = sprintDetails.locator('.sprint-task:has-text("Implement Login Feature v2")');
    
    await taskEl.locator('button[title="Remove task"]').click();
    
    // Check if it was removed
    await expect(taskEl).not.toBeVisible();
  });

  test('should disable AI sprint generation without a plan or if sprints exist', async () => {
    // The button should be disabled with a specific title since we already have sprints 
    // and no plan file uploaded.
    const aiBtn = page.locator('button:has-text("Sprint with AI")');
    await expect(aiBtn).toBeVisible();
    await expect(aiBtn).toHaveCSS('cursor', 'not-allowed');
    await expect(aiBtn).toHaveAttribute('title', /A sprint has already been started|Upload a project plan first/i);
  });
});
