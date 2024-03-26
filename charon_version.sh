GIT_TAG=$(git describe --exact-match --tags HEAD 2>/dev/null)
APP_VERSION=$(grep 'var version' app/version/version.go | cut -d'"' -f2)

git diff-files --quiet
DIRTY=$?

FINAL_TAG=""
if [[ ${#GIT_TAG} == 0 ]]; then
    FINAL_TAG=$APP_VERSION

    if [[ $DIRTY == 1 ]]; then
        FINAL_TAG="${FINAL_TAG}-DIRTY"
    fi
else
    FINAL_TAG=$GIT_TAG

    if [[ $DIRTY == 1 ]]; then
        FINAL_TAG="${FINAL_TAG}-DIRTY"
    fi

fi

echo $FINAL_TAG
