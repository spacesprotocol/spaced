# Contributing to Spaces

This document is adapted from Bitcoin Core [contributing guide](https://github.com/bitcoin/bitcoin/blob/master/CONTRIBUTING.md). Everyone is welcome to contribute towards development in the form of peer review, testing and patches. This document explains the practical process and guidelines for contributing.

## Getting started

Reviewing and testing is highly valued and the most effective way you can contribute as a new contributor. It also will teach you much more about the code and process than opening pull requests.


### Good First Issue Label

The purpose of the good first issue label is to highlight which issues are suitable for a new contributor without a deep understanding of the codebase.

However, good first issues can be solved by anyone. If they remain unsolved for a longer time, a frequent contributor might address them.

You do not need to request permission to start working on an issue. However, you are encouraged to leave a comment if you are planning to work on it. This will help other contributors monitor which issues are actively being addressed and is also an effective way to request assistance if and when you need it.


## Communication Channels

You can join the [spaces telegram](https://t.me/spacesprotocol).

Discussion about codebase improvements happens in GitHub issues and pull requests.

## Contributor Workflow

The codebase is maintained using the "contributor workflow" where everyone without exception contributes patch proposals using "pull requests" (PRs). This facilitates social contribution, easy testing and peer review.

To contribute a patch, the workflow is as follows:

1. Fork repository (only for the first time)
2. Create topic branch
3. Commit patches

## Squashing Commits

If your pull request contains fixup commits (commits that change the same line of code repeatedly) or too fine-grained commits, it's a good practice to squash your commits to better prepare them for review. 

Learn how to write [good commit messages](https://cbea.ms/git-commit/)

## Pull Request Philosophy

It's a good practice to make Patchsets focused. For example, a pull request could add a feature, fix a bug, or refactor code; but not a mixture. Please also avoid super pull requests which attempt to do too much, are overly large, or overly complex as this makes review difficult.


## Copyright

By contributing to this repository, you agree to license your work under the MIT license unless specified otherwise in contrib/debian/copyright or at the top of the file itself. Any work contributed where you are not the original author must contain its license header with the original author(s) and source.

