for iid in 123 124 125; do echo "=== MR !$iid VIEW ==="; glab mr view $iid -R group/project --comments -F json > /tmp/work/mr-$iid-view.json 2>/tmp/work/mr-$iid-view.err; done
