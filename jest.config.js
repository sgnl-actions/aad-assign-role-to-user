export default {
  testEnvironment: 'node',
  transform: {},
  testMatch: [
    '**/tests/**/*.test.js',
    '**/tests/**/*.test.mjs'
  ],
  moduleFileExtensions: ['js', 'mjs', 'json'],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.js']
};