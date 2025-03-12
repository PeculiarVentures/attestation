/** @type {import('ts-jest').JestConfigWithTsJest} */
// eslint-disable-next-line no-undef
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  rootDir: '.',
  transformIgnorePatterns: ['<rootDir>/node_modules/'],
  transform: {
    '^.+\\.tsx?$': 'ts-jest',
  },
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  testMatch: ['<rootDir>/packages/*/src/**/*.spec.ts'],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov'],
};
