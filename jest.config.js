module.exports = {
  rootDir: '.',
  roots: ['<rootDir>/server', '<rootDir>/common'],
  testMatch: ['**/*.test.ts', '**/*.test.tsx'],
  testEnvironment: 'node',
  clearMocks: true,
  transform: {
    '^.+\\.(js|ts|tsx)$': '<rootDir>/../../src/dev/jest/babel_transform.js',
  },
};
