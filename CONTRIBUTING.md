# Contributing to Solana Pay

Thank you for your interest in contributing to Solana Pay! All contributions are welcome no
matter how big or small. This includes (but is not limited to) filing issues,
adding documentation, fixing bugs, creating examples, and implementing features.

## Finding issues to work on

If you're looking to get started,
check out [good first issues](https://github.com/solana-foundation/solana-pay/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
or issues where [help is wanted](https://github.com/solana-foundation/solana-pay/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22).
For simple documentation changes or typos, feel free to just open a pull request.

## Choosing an issue

If you'd like to contribute, please claim an issue by commenting, forking, and
opening a pull request, even if empty. This allows the maintainers to track who
is working on what issue as to not overlap work.

## Issue Guidelines

Please follow these guidelines:

Before coding:

- choose a branch name that describes the issue you're working on
- enable [commit signing](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)

While coding:

- Submit a draft PR asap
- Only change code directly relevant to your PR. Sometimes you might find some code that could really need some refactoring. However, if it's not relevant to your PR, do not touch it. File an issue instead. This allows the reviewer to focus on a single problem at a time.
- If you write comments, do not exceed 80 chars per line. This allows contributors who work with multiple open windows to still read the comments without horizontally scrolling.
- Write adversarial tests. For example, if you're adding a new account type, do not only write tests where the instruction succeeds. Also write tests that test whether the instruction fails, if a check inside the new type is violated.

## Setting Up Your Development Environment

1. Fork the repository and clone it locally.
2. Install dependencies:
   ```
   npm install
   ```
3. Run tests to ensure everything works:
   ```
   npm test
   ```

## Pull Request Process

- Ensure your PR description clearly explains the problem and solution.
- Reference any related issues by number (e.g., "Closes #123").
- Make sure all tests pass before requesting a review.
- Respond to review comments and make necessary changes.

## Coding Style

- Follow the existing code style.
- Use Prettier for formatting.
  ```
  npm run fmt
  ```

## Tests

- Add or update tests for your changes.
- Tests are located in the `core/test/` directory.
- Run tests with:
  ```
  npm test
  ```

## Reporting Bugs or Requesting Features

- Please use [GitHub Issues](link-to-issues) to report bugs or request features.
- Include as much detail as possible.
