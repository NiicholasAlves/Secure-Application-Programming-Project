// playwright.config.js
// Basic Playwright config for local testing

const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  use: {
    baseURL: 'http://localhost:3000',
    headless: true,
  },
  timeout: 30000,
});
