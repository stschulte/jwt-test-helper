import eslint from "@eslint/js";
import gitignore from "eslint-config-flat-gitignore";
import perfectionist from 'eslint-plugin-perfectionist'
import tseslint from "typescript-eslint";

export default tseslint.config(
  gitignore(),
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    // disable type-aware linting on JS files
    files: ['**/*.js'],
    ...tseslint.configs.disableTypeChecked,
  },
  perfectionist.configs["recommended-natural"]
);
