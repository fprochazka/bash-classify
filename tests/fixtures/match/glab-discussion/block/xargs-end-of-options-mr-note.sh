printf '%s\n' 42 | xargs -I{} -- glab mr note {} -m "looks good to me"
