#!/bin/bash
cd "$SRCROOT"
git=$(sh /etc/profile; which git)
number_of_commits=$("$git" rev-list HEAD --count)
git_release_version=$("$git" describe --tags --always --abbrev=0)

sed -i -e "/BUILD_NUMBER =/ s/= .*/= $git_release_version/" Config.xcconfig
sed -i -e "/VERSION =/ s/= .*/= $number_of_commits/" Config.xcconfig
rm -f Config.xcconfig-e
