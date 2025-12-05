// tests/auth.spec.js
// Automated UI tests for the SECURE version using Playwright

const { test, expect } = require('@playwright/test');

test('secure login succeeds with valid credentials', async ({ page }) => {
  await page.goto('/login');

  await page.fill('input[name="email"]', 'admin@example.com');
  await page.fill('input[name="password"]', 'password123');
  await page.click('button[type="submit"]');

  await expect(page.locator('text=Login successful (Secure)')).toBeVisible();
});

test('secure login blocks SQL injection password', async ({ page }) => {
  await page.goto('/login');

  await page.fill('input[name="email"]', 'admin@example.com');
  await page.fill('input[name="password"]', `' OR '1'='1`);
  await page.click('button[type="submit"]');

  await expect(page.locator('text=Invalid email or password')).toBeVisible();
});
