module.exports = {
  rootDir: '.',
  roots: ['<rootDir>/server', '<rootDir>/common', '<rootDir>/public'],
  testMatch: ['**/*.test.ts', '**/*.test.tsx'],
  // Server and common tests run in node; a public component test opts into
  // jsdom with a `@jest-environment jsdom` docblock.
  testEnvironment: 'node',
  // Sets the `_isJest` global EuiDataGrid looks for (see public/jest_setup.js).
  setupFiles: ['<rootDir>/public/jest_setup.js'],
  clearMocks: true,
  transform: {
    '^.+\\.(js|ts|tsx)$': '<rootDir>/../../src/dev/jest/babel_transform.js',
  },
  // Same EUI/style mapping as the upstream src/dev/jest/config.js, so public
  // components render against the EUI test build without the SCSS pipeline.
  moduleNameMapper: {
    '@elastic/eui$': '<rootDir>/../../node_modules/@elastic/eui/test-env',
    '@elastic/eui/lib/(.*)?': '<rootDir>/../../node_modules/@elastic/eui/test-env/$1',
    '\\.(css|less|scss)$': '<rootDir>/../../src/dev/jest/mocks/style_mock.js',
    '\\.(jpg|jpeg|png|gif|svg|woff|woff2)$': '<rootDir>/../../src/dev/jest/mocks/file_mock.js',
  },
};
