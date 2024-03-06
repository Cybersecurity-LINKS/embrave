#Simulation of a process that extends the IMA log
#Used to test the incremental IMA log verification
#This script sleeps for a random timer between T_MIX and TMAX+1 and the execute some istructions to extend the IMA log
T_MIX=2
T_MAX=8
N=1000
for ((i=1; i<=$N; i++)) #sudo valgrind --leak-check=yes
do
    var=$(( ($RANDOM % $T_MAX) + $T_MIX ))
    echo "Sleep: $var"
    sleep $var
    sudo date > tmp.txt
    sudo cat tmp.txt > tmp2
    sudo rm tmp.txt tmp2
done