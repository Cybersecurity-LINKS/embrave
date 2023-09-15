for ((i=1; i<=1000; i++)) #sudo valgrind --leak-check=yes
do
    var=$(( ($RANDOM % 60) + 2 ))
    echo "Sleep: $var"
    sleep $var
    sudo date > tmp.txt
    sudo cat tmp.txt > aaa
    sudo rm tmp.txt aaa
done