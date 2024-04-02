for ((i=1; i<=1000; i++)) #sudo valgrind --leak-check=yes
do
    ./build/agent.build/attester_server
done