// @ts-check
import baseConfig from '@peculiar/eslint-config-base';
import tseslint from 'typescript-eslint';

export default tseslint.config([
  ...baseConfig,
  {
    rules: {
      'import/no-unresolved': ['off'],
      '@stylistic/object-curly-newline': ['off'],
      '@stylistic/operator-linebreak': ['off'],
      '@stylistic/padding-line-between-statements': ['off'],
      '@typescript-eslint/naming-convention': ['off'],
    },
  },
]);
