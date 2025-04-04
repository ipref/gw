alias router1='ip netns exec router1'
alias gw7='ip netns exec gw7'
alias gw8='ip netns exec gw8'
alias host711='ip netns exec host711'
alias host822='ip netns exec host822'

for prefix in GW{,7EN,8EN}; do
    name=${prefix}_IPv
    case "${!name}" in
        4)
            ;;
        6)
            ;;
        *)
            declare ${prefix}_IPv=4
            ;;
    esac
    case "${!name}" in
        4)
            declare ${prefix}_IP_PREFIX=
            declare ${prefix}_SUBNET_BITS=24
            ;;
        6)
            declare ${prefix}_IP_PREFIX="fc00::"
            declare ${prefix}_SUBNET_BITS=120
            ;;
    esac
done

export GW{,7EN,8EN}_{IPv,IP_PREFIX,SUBNET_BITS}

gw_args=(
    # -debug gw,pkt,tun,mapper
    # -time-stamps
    -trace
    # -test-mapper
)

function run-gw7 {
    gw7 go run . \
        -data /var/lib/ipref/gw7 \
        -gateway "${GW_IP_PREFIX}192.168.11.97" \
        -gateway-port 1046 \
        -encode-net "${GW7EN_IP_PREFIX}10.240.0.0/$(($GW7EN_SUBNET_BITS - 12))" \
        -mapper-socket /run/ipref/gw7/mapper.sock \
        "${gw_args[@]}"
}
function run-gw8 {
    gw8 go run . \
        -debug "$GW_DEBUG_LIST" \
        -data /var/lib/ipref/gw8 \
        -gateway "${GW_IP_PREFIX}192.168.12.98" \
        -gateway-port 1045 \
        -encode-net "${GW8EN_IP_PREFIX}10.240.0.0/$(($GW8EN_SUBNET_BITS - 12))" \
        -mapper-socket /run/ipref/gw8/mapper.sock \
        "${gw_args[@]}"
}
