import tsParser from "@typescript-eslint/parser";

export default [
  {
    files: ["packages/server/src/**/*.ts"],
    languageOptions: {
      ecmaVersion: "latest",
      parser: tsParser,
      sourceType: "module",
    },
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector: "ThrowStatement",
          message: "Return Result values from okay-error instead of throwing.",
        },
      ],
      "no-throw-literal": "error",
    },
  },
];
