#!/bin/sh -l

set -e
export PATH="${PATH}:/usr/local/go/bin"

printenv

cd "${GITHUB_WORKSPACE}"



#curl --request POST \
#          --url https://api.github.com/repos/${{ github.repository }}/issues \
#          --header 'authorization: Bearer ${{ secrets.GITHUB_TOKEN }}' \
#          --header 'content-type: application/json' \
#          --data '{
#            "title": "Automated issue for commit: ${{ github.sha }}",
#            "body": "This issue was automatically created by the GitHub Action workflow **${{ github.workflow }}**. \n\n The commit hash was: _${{ github.sha }}_."
#            }' \
#          --fail
