# practicalvm

This repo contains all of the scripts used in Practical Vulnerability Management (No Starch Press, 2020)

## `book-scripts` folder
This folder contains code listings **as they appear in the published book**. These scripts are also prepended with their listing IDs as used in the book.

Scripts in the root directory of the repo may have been changed (and hopefully improved) since the book was published.

## News
### 2/20/21
I've renamed the default branch from `master` to `main`. To update your local environment, please run the following:
```
git branch -m master main
git fetch origin
git branch -u origin/main main
```
### 1/2/2021
As promised, [here](docs/gvm-11.md) is a basic doc on installing GVM 11 for use with this VM system.
### 1/1/2021
Happy new year! :tada: I've updated a few scripts so you can now use them with GVM 11. I'll have another doc up soon with a few notes on installing GVM 11 from mrazavi's packages at https://launchpad.net/~mrazavi/+archive/ubuntu/gvm.
