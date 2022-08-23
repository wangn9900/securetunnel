<?php
require_once __DIR__ . '/../../../../../init.php';
require_once __DIR__ . '/../../../../addons/PortForwardGo/func.php';

use Illuminate\Database\Capsule\Manager as Capsule;

if (!defined("WHMCS") || !isset($_REQUEST['id']) || !isset($_REQUEST['rules'])) {
    die("This file cannot be accessed directly");
} else {
    $sql = Capsule::table("mod_PortForwardGo_Rules")->where("sid", $_REQUEST['id'])->whereIn('id', explode(" ", $_REQUEST['rules']));
    if (!$sql->exists()) {
        die("404 Not Found");
    }
    $config = PortForwardGo_GetConfigModule();

    if (isset($_REQUEST['get_config'])) {
        $rules = $sql->get();
        $conf = [];

        $protocol = [
            "secure_server" => "secure_client",
            "secure_client" => "secure_server",
            "websocket_server" => "websocket_client",
            "websocket_client" => "websocket_server",
            "quic_server" => "quic_client",
            "quic_client" => "quic_server",
            "tls_server" => "tls_client",
            "tls_client" => "tls_server",
            "cloudflare" => "cloudflare",
        ];

        $sql_nodes = Capsule::table("mod_PortForwardGo_Node")->get();
        $nodes = [];
        foreach ($sql_nodes as $node) {
            $nodes[$node->id] = $node;
        }
        foreach ($rules as $rule) {
            $conf[(string)$rule->id]["Mode"] = 0;
            $conf[(string)$rule->id]["ProxyProtocol"] = 0;

            if (in_array($rule->protocol, ["secure_server", "secure_client"])) {
                $conf[(string)$rule->id]["Key"] = empty($config['securekey']) ? $config['key'] : $config['securekey'];
                $conf[(string)$rule->id]["Pool"] = 30;
            } else if (in_array($rule->protocol, ["quic_client", "tls_client", "websocket_client"])) {
                $conf[(string)$rule->id]["Cert"] = "ssl/" . $rule->id . '.pem';
                $conf[(string)$rule->id]["Key"] = "ssl/" . $rule->id . '.key';
            } else if (in_array($rule->protocol, ["cloudflare"])) {
                $conf[(string)$rule->id]["Cert"] = "";
                $conf[(string)$rule->id]["Key"] = "";
                $conf[(string)$rule->id]["Paths"]["/ws"] = "IP:Port";
                $conf[(string)$rule->id]["Paths"]["/ws2"] = "IP:Port";
            }

            $conf[(string)$rule->id]["Protocol"] = $protocol[$rule->protocol];

            if (in_array($rule->protocol, ["cloudflare"])) {
                $conf[(string)$rule->id]["Listen"] = (int)$rule->remoteport;
                $conf[(string)$rule->id]["MinSpeed"] = 0;
            } else if (strpos($protocol[$rule->protocol], "client") == false) {
                $conf[(string)$rule->id]["Listen"] = (int)$rule->remoteport;
                $conf[(string)$rule->id]["Targets"][0]['Host'] = "127.0.0.1";
                $conf[(string)$rule->id]["Targets"][0]['Port'] = 8080;
            } else {
                $conf[(string)$rule->id]["Listen"] = (int)$rule->port;
                $conf[(string)$rule->id]["Targets"][0]['Host'] = $nodes[$rule->node]->addr;
                $conf[(string)$rule->id]["Targets"][0]['Port'] = (int)$rule->port;
            }
        }
        $file = json_encode($conf, JSON_PRETTY_PRINT);
        header("Content-type: application/octet-stream");
        header("Accept-Ranges: bytes");
        header("Accept-Length: " . strlen($file));
        header("Content-Disposition: attachment; filename=config.json");
        exit($file);
    }
    $config_url = PortForwardGo_GetSystemURL() . "modules/servers/PortForwardGoClient/static/script/securetunnel.php?get_config=yes&id=" . $_REQUEST['id'] . '&rules=' .  urlencode($_REQUEST['rules']);
?>
    #!/bin/sh
    clear
    Font_Black="\033[30m";
    Font_Red="\033[31m";
    Font_Green="\033[32m";
    Font_Yellow="\033[33m";
    Font_Blue="\033[34m";
    Font_Purple="\033[35m";
    Font_SkyBlue="\033[36m";
    Font_White="\033[37m";
    Font_Suffix="\033[0m";
    config="<?php echo $config_url; ?>"
    version=$(wget -qO- https://raw.githubusercontent.com/wangn9900/securetunnel/main/jiancha | grep "tag_name" | head -n 1| awk -F ":" '{print $2}'| awk -F "," '{print $1}' | sed 's/\"//g;s/,//g;s/ //g'| awk -F "v" '{print $2}')

    echo -e "${Font_SkyBlue}SecureTunnel installation script${Font_Suffix}";
    echo -e "${Font_Yellow} ** Checking system info...${Font_Suffix}";

    os=`uname -s | tr [:upper:] [:lower:]`;
    arch=`uname -m`;
    cpu_flags=$(cat /proc/cpuinfo | grep flags | head -n 1 | awk -F ':' '{print $2}')

    case ${arch} in
    x86)
    arch="386"
    ;;
    x86_64)
    if [[ ${cpu_flags} == *avx512* ]]; then
    arch="amd64v4"
    elif [[ ${cpu_flags} == *avx2* ]]; then
    arch="amd64v3"
    elif [[ ${cpu_flags} == *sse3* ]]; then
    arch="amd64v2"
    else
    arch="amd64v1"
    fi
    ;;
    aarch64)
    arch="arm64"
    ;;
    esac

    url="https://github.com/wangn9900/securetunnel/releases/download/v1.3.6/SecureTunnel_"${version}"_"${os}"_"${arch}".tar.gz";
    echo -e "${Font_Yellow} ** Checking wget...${Font_Suffix}";

    wget -V> /dev/null 2>&1 ;
    if [ $? -ne 0 ];then
    echo -e "${Font_Red} [Error] Please install wget${Font_Suffix}"
    exit 1
    fi
    echo -e "${Font_Green} [Success] Wget found${Font_Suffix}"

    echo -e "${Font_Yellow} ** Prepare for installation...${Font_Suffix}"
    systemctl stop SecureTunnel > /dev/null 2>&1

    echo -e "${Font_Yellow} ** Creating Program Dictionary...${Font_Suffix}"
    if [ ! -d "/opt/SecureTunnel/" ];then
    mkdir /opt/SecureTunnel/ > /dev/null 2>&1
    mkdir /opt/SecureTunnel/ssl/ > /dev/null 2>&1
    fi

    echo -e "${Font_Yellow} ** Showing the node infomation${Font_Suffix}"
    echo -e " Version: " ${version}

    echo -e "${Font_Yellow} ** Downloading files and configuring...${Font_Suffix}"
    if [[ -a "/usr/bin/systemctl" ]] || [[ -a "/bin/systemctl" ]];then
    wget -qO /etc/systemd/system/SecureTunnel.service https://raw.githubusercontent.com/wangn9900/securetunnel/main/SecureTunnel.service
    ln -sf /etc/systemd/system/SecureTunnel.service /etc/systemd/system/multi-user.target.wants/SecureTunnel.service
    systemctl daemon-reload > /dev/null 2>&1
    systemctl enable SecureTunnel > /dev/null 2>&1
    else
    echo -e "${Font_Yellow}Not Found systemd, skip to configure system service. ${Font_Suffix}"
    fi

    wget -qO /usr/bin/update-securetunnel https://raw.githubusercontent.com/wangn9900/securetunnel/main/update-script
    wget -qO /opt/SecureTunnel/setting.json https://raw.githubusercontent.com/wangn9900/securetunnel/main/default-setting.json
    chmod 777 /usr/bin/update-securetunnel
    wget -qO /tmp/SecureTunnel.tar.gz ${url}
    tar -xvzf /tmp/SecureTunnel.tar.gz -C /tmp/ > /dev/null 2>&1
    rm -rf /opt/SecureTunnel/SecureTunnel > /dev/null 2>&1
    mv /tmp/SecureTunnel /opt/SecureTunnel/SecureTunnel > /dev/null 2>&1
    rm -rf /tmp/* > /dev/null 2>&1
    chmod 777 /opt/SecureTunnel/SecureTunnel
    wget -qO /opt/SecureTunnel/config.json "${config}"

    wget -qO /tmp/panel.tar.gz "https://github.com/wangn9900/securetunnel/releases/download/v1.3.6//SecureTunnel-v${version}.tar.gz"
    tar -xvzf /tmp/panel.tar.gz -C /tmp/ > /dev/null 2>&1
    rm -rf /opt/SecureTunnel/public > /dev/null 2>&1
    mv -f /tmp/SecureTunnel-v${version}/public /opt/SecureTunnel/public > /dev/null 2>&1
    rm -rf /tmp/* > /dev/null 2>&1

    echo -e "${Font_Yellow} ** Configuring system...${Font_Suffix}"

    read -ep "Do you want to use our sysctl.conf ? [y/n]" ask
    if [[ "${ask}" == "y" || "${ask}" == "Y" ]];then
    echo "# nofile
    vm.swappiness = 10
    fs.file-max = 1000000
    fs.inotify.max_user_instances = 8192
    fs.pipe-max-size = 1048576
    fs.pipe-user-pages-hard = 0
    fs.pipe-user-pages-soft = 0
    net.ipv4.conf.all.rp_filter = 0
    net.ipv4.conf.default.rp_filter = 0

    # socket status
    net.ipv4.tcp_syncookies = 1
    net.ipv4.tcp_fin_timeout = 30
    net.ipv4.tcp_tw_timeout = 10
    net.ipv4.tcp_tw_reuse = 1
    net.ipv4.tcp_timestamps = 1
    net.ipv4.tcp_keepalive_time = 1200
    net.ipv4.tcp_keepalive_probes = 3
    net.ipv4.tcp_keepalive_intvl = 15
    net.ipv4.ip_local_port_range = 1024 65535
    net.ipv4.tcp_max_syn_backlog = 8192
    net.ipv4.tcp_max_tw_buckets = 3000
    net.ipv4.route.gc_timeout = 100
    net.ipv4.tcp_syn_retries = 2
    net.ipv4.tcp_synack_retries = 2

    # tcp window
    net.core.wmem_default = 262144
    net.core.wmem_max = 67108864
    net.core.somaxconn = 3276800
    net.core.optmem_max = 81920
    net.core.rmem_default = 262144
    net.core.rmem_max = 67108864
    net.core.netdev_max_backlog = 400000
    net.core.netdev_budget = 600
    net.ipv4.tcp_max_orphans = 3276800

    # forward ipv4
    net.ipv4.conf.all.route_localnet=1
    net.ipv4.tcp_no_metrics_save=1
    net.ipv4.tcp_ecn=0
    net.ipv4.tcp_frto=0
    net.ipv4.tcp_mtu_probing=0
    net.ipv4.tcp_rfc1337=0
    net.ipv4.tcp_sack=1
    net.ipv4.tcp_fack=1
    net.ipv4.tcp_window_scaling=1
    net.ipv4.tcp_adv_win_scale=1
    net.ipv4.tcp_moderate_rcvbuf=1
    net.ipv4.tcp_mem = 786432 2097152 3145728
    net.ipv4.tcp_rmem = 4096 524288 67108864
    net.ipv4.tcp_wmem = 4096 524288 67108864
    net.ipv4.udp_rmem_min=8192
    net.ipv4.udp_wmem_min=8192
    net.core.default_qdisc=fq
    net.ipv4.tcp_congestion_control=bbr

    # deny attack
    net.inet.udp.checksum=1

    # netfiliter iptables
    net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
    net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
    net.netfilter.nf_conntrack_tcp_timeout_close_wait = 15
    net.netfilter.nf_conntrack_tcp_timeout_established = 350
    net.netfilter.nf_conntrack_max = 25000000
    net.netfilter.nf_conntrack_buckets = 25000000">/etc/sysctl.conf

    echo "* soft nofile 1048576
    * hard nofile 1048576
    * soft nproc 1048576
    * hard nproc 1048576
    * soft core 1048576
    * hard core 1048576
    * hard memlock unlimited
    * soft memlock unlimited
    ">/etc/security/limits.conf

    sysctl -p > /dev/null 2>&1
    sysctl --system > /dev/null 2>&1
    fi

    if [[ -f "/usr/sbin/iptables-save" ]] && [[ "$(iptables-save)" != "" ]];then
    echo -e "${Font_Red} Please stop your firewall. ${Font_Suffix}"
    fi

    echo -e "${Font_SkyBlue} Please edit the configuration on webpanel ${Font_Suffix}"
    echo -e "${Font_Yellow} ** Starting Program...${Font_Suffix}"
    systemctl start SecureTunnel > /dev/null 2>&1

    echo -e "${Font_Green} [Success] Completed installation${Font_Suffix}"
    echo -e "${Font_SkyBlue} [Web Panel] http://your_ip:14514/ Username: admin Password: SecureTunnelAdmin Setting-file: /opt/SecureTunnel/setting.json"
    echo -e "${Font_SkyBlue} [Tip] Please Reboot${Font_Suffix}"
<?php } ?>