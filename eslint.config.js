import baseConfig from '@kitiumai/lint/eslint/base';
import tsConfig from '@kitiumai/lint/eslint/typescript';

export default [
  { ignores: ['dist', 'build', 'node_modules', 'coverage', '**/*.d.ts', 'src/__tests__/**/*'] },
  ...baseConfig,
  ...tsConfig,
  {
    // Library-specific rules and overrides
    rules: {
      complexity: ['warn', 10],
      'max-lines-per-function': ['warn', { max: 100 }],
      'max-statements': 'off',
      'no-nested-ternary': 'warn',
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-inferrable-types': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/array-type': 'off',
      '@typescript-eslint/prefer-readonly': 'off',
      '@typescript-eslint/consistent-type-definitions': 'off',
      '@typescript-eslint/consistent-type-imports': 'off',
      '@typescript-eslint/naming-convention': 'off',
      '@typescript-eslint/prefer-nullish-coalescing': 'off',
      '@typescript-eslint/require-await': 'off',
      'import/order': 'off',
      'no-duplicate-imports': 'off',
      'simple-import-sort/imports': 'off',
      'simple-import-sort/exports': 'off',
      'unicorn/prevent-abbreviations': 'off',
      // Override no-restricted-imports with correct format
      'no-restricted-imports': [
        'warn',
        {
          patterns: ['../../*', '../../../*'],
        },
      ],
    },
  },
];
