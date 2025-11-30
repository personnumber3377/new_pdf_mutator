DIR=./corpus
awk -v d="$DIR" '{print d "/" $1}' DIB_HIT.txt | \
    xargs -I{} stat --printf="%s %n\n" {} | sort -n # | head -1