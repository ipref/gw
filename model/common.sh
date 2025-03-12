alias gw7='ip netns exec gw7'
alias gw8='ip netns exec gw8'
alias host711='ip netns exec host711'
alias host822='ip netns exec host822'

function run-gw7 {
    gw7 go run . \
        -data /var/lib/ipref/gw7 \
        -gateway 192.168.10.97 \
        -mapper-socket /run/ipref/gw7/mapper.sock \
        -time-stamps -trace
}
function run-gw8 {
    gw8 go run . \
        -data /var/lib/ipref/gw8 \
        -gateway 192.168.10.98 \
        -mapper-socket /run/ipref/gw8/mapper.sock \
        -time-stamps -trace
}
