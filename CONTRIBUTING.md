# Contributing Guide

Thank you for your interest in contributing to [DeRec Protocol!](https://github.com/derecalliance/protocol/blob/main/protocol.md) 🚀

All contributions are welcome, regardless of your experience level.

## New to the codebase? No worries! 🎉

Contributing to open source doesn't always mean writing code. Here are some great ways you can help:

- 🐛 **Report bugs** - Help us identify and fix issues.
- 📚 **Improve documentation** - Make our docs clearer and more comprehensive.
- 📢 **Spread the word** - Share the project with your network.
- ✨ **Add features** - Implement new functionality.
- 🔧 **Submit patches** - Fix existing issues and improve code.

Every contribution, no matter how small, makes a difference!

## Support Questions

Need help getting started or running into issues? Here's how to get support:

1. **Check the documentation first** 📖
   - Review the README for use instructions.
   - Browse existing issues for similar problems.

2. **Still stuck? Reach out!** 💬
   - Open a new discussion for general questions.
   - Create a support issue for specific problems.

We're here to help you succeed!

## Reporting Issues

If you find a bug or have a feature request, please open an issue with the following information:

- A clear and descriptive title.
- Steps to reproduce the issue (if applicable).
- Expected and actual behavior.
- Any relevant logs, screenshots, or code snippets.

## Submitting Patches or contributions

- Include tests if your patch is supposed to solve a bug, and explain clearly under which circumstances the bug happens. Make sure the test fails without your patch.

### First time setup

1. **Configure git with your username and email:**
   ```shell
   git config --global user.name 'your name'
   git config --global user.email 'your email'
   ```
2. **Fork Project to your GitHub account by clicking the [Fork button](https://github.com/derecalliance/lib-rust/fork).**

3. **[Clone](https://help.github.com/articles/fork-a-repo/#step-2-create-a-local-clone-of-your-fork) your GitHub fork locally:**
   ```bash
   git clone https://github.com/{username}/derecalliance/lib-rust
   cd lib-rust
   ```

4. **Add the main repository as a remote to update later:**
   ```bash
   git remote add lib-rust https://github.com/derecalliance/lib-rust
   cd lib-rust
   ```

5. **[Install rust](https://doc.rust-lang.org/book/ch01-01-installation.html#installation) and verify your versions:**
   ```bash
   rustc --version   # should output 1.87.0 
   cargo --version   # should output 1.87.0 
   ```

6. **Build Project and run test to verify setup:**
   ```
   cargo build
   cargo test
   ```

7. **Start coding**
   - Create a new branch to identify the issue (e.g. `fix_for#123`).
   - Include tests that cover any code changes you make. Make sure the test fails without your patch.
   - Push your commits and [create a pull request](https://help.github.com/articles/creating-a-pull-request/).
   - **celebrate! 🎉** --We'll review it as soon as possible and get back to you.

**Thank you for contributing to DeRec Protocol!** 💪

## Code Style

- Follow the existing code style.
- Use meaningful variable and function names.
- Write comments where necessary.
