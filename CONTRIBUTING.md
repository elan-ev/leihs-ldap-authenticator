Contributing to the Leihs LDAP Authenticator
============================================

As an open source project, the Leihs LDAP Authenticator welcomes contributions of many forms.
Examples of contributions include:

- Code patches
- Documentation improvements
- Bug reports and patch reviews


Being Pragmatic
---------------

For every rule, there is an exception.
If you find that there is a good reason one of the following rules does not apply to you,
please bring it up and explain why.
We like to be pragmatic if necessary instead of blindly follow rules.


Provide Necessary Information
-----------------------------

If you provide a patch, please also provide an explanation of the reasoning behind this patch.
It is much easier to understand and review code if you know its intention upfront.
If a pull request relates to an existing issue, please also link that issue.

If you want to make us happy, please also provide this reasoning as part of your git commit messages.


Tests
-----

sentinel5dl comes with a set of unit tests.
Passing these tests is a requirement for all contributions.
These tests are also run automatically on our CI system.

To run tests locally, use::

    python -m tests

If the CI tests on your pull request fail and you are sure it is not caused by your patch, please complain.
Errors happen and we can easily trigger a new build.
Your patch cannot be merged without these tests passing.


Documentation
-------------

If necessary, say for instance you modify the API,
please also provide the documentation for your change as part of your pull request.
Once a pull request is merged, the documentation should match that code.


Internationalization
--------------------

```
❯ find leihsldap/i18n/*
leihsldap/i18n/error-de.yml
leihsldap/i18n/error-en.yml
leihsldap/i18n/i18n-de.yml
leihsldap/i18n/i18n-en.yml
```


Reviews
-------

A reviewer will be assigned to your pull request to ensure that there are no issues.
Once everything is fine, the reviewer will merge the pull request.
Please communicate with the reviewer to address any issues.

Please remember that reviewers are only human as well.


Merging
-------

We prefer to `rebase and merge pull requests`_ if the contribution has a sane commit history
or to `squash and merge your pull request commits`_ if they have not.
This is meant to keep the overall commit history as clean as possible.
If you prefer a specific merge mode for any reason, please indicate that on the pull request.


Checklist
---------

- Pull request `closes an accompanying issue`_ if one exists
- Pull request has a proper title and description
- Appropriate documentation is included
- Code passes automatic tests
- The pull request has a clean commit history
- Commits have a `proper commit message`_ (title and body)


.. _rebase and merge pull requests: https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-request-merges#rebase-and-merge-your-pull-request-commits
.. _squash and merge your pull request commits: https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-request-merges#squash-and-merge-your-pull-request-commits
.. _closes an accompanying issue: https://help.github.com/en/articles/closing-issues-using-keywords
.. _proper commit message: https://chris.beams.io/posts/git-commit/
