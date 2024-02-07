# Offline install k8s 1.27.1

## 一、系統環境建置

**參考自 : https://blog.51cto.com/flyfish225/6195237**

### 1. 編輯k8s node hostname


```
系統：
    Centos 7.9


sudo vim /etc/hosts

-----------------------------------


${master node ip}    master01
${worker node ip}    worker01


-----------------------------------
編輯完host需 sudo reboot後hosts名才會改變，

本次只部署master01 node
-----------------------------------

```

### 2. 下載建置k8s所需資源
```
下載kubernetes1.27.+的二進制包
github二進制包下載地址：https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.27.md

----------------------------------------------------------------------
wget https://dl.k8s.io/v1.27.1/kubernetes-server-linux-amd64.tar.gz
----------------------------------------------------------------------

2.下載etcdctl二進制包
github二進制包下載地址：https://github.com/etcd-io/etcd/releases
 
---------------------------------------------------------------------------------------------------------
wget https://github.com/etcd-io/etcd/releases/download/v3.5.8/etcd-v3.5.8-linux-amd64.tar.gz
---------------------------------------------------------------------------------------------------------

3.docker-ce二進制包下載地址
二進制包下載地址：https://download.docker.com/linux/static/stable/x86_64/
 
这里需要下載20.10.+版本
 
---------------------------------------------------------------------------------------------------------
wget https://download.docker.com/linux/static/stable/x86_64/docker-20.10.23.tgz
---------------------------------------------------------------------------------------------------------

4.下載cri-docker 
二進制包下載地址：https://github.com/Mirantis/cri-dockerd/releases/
 
--------------------------------------------------------------------------------------------------------------------------------------------
wget  https://ghproxy.com/https://github.com/Mirantis/cri-dockerd/releases/download/v0.2.6/cri-dockerd-0.2.6.amd64.tgz
--------------------------------------------------------------------------------------------------------------------------------------------

5.containerd二進制包下載
github下載地址：https://github.com/containerd/containerd/releases
 
containerd下載时下載带cni插件的二進制包。

--------------------------------------------------------------------------------------------------------------------------------------------
wget https://github.com/containerd/containerd/releases/download/v1.6.6/cri-containerd-cni-1.6.6-linux-amd64.tar.gz
--------------------------------------------------------------------------------------------------------------------------------------------

6.下載cfssl二進制包
github二進制包下載地址：https://github.com/cloudflare/cfssl/releases

---------------------------------------------------------------------------------------------------------
wget https://github.com/cloudflare/cfssl/releases/download/v1.6.1/cfssl_1.6.1_linux_amd64
wget https://github.com/cloudflare/cfssl/releases/download/v1.6.1/cfssljson_1.6.1_linux_amd64
wget https://github.com/cloudflare/cfssl/releases/download/v1.6.1/cfssl-certinfo_1.6.1_linux_amd64
---------------------------------------------------------------------------------------------------------

7.cni插件下載
github下載地址：https://github.com/containernetworking/plugins/releases
 
----------------------------------------------------------------------------------------------------------------
wget https://github.com/containernetworking/plugins/releases/download/v1.1.1/cni-plugins-linux-amd64-v1.1.1.tgz
----------------------------------------------------------------------------------------------------------------

8.crictl客户端二進制下載
github下載：https://github.com/kubernetes-sigs/cri-tools/releases
 
--------------------------------------------------------------------------------------------------------------------------------------------
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.24.2/crictl-v1.24.2-linux-amd64.tar.gz
--------------------------------------------------------------------------------------------------------------------------------------------

```

### 3. vm環境配置

```
# 安装依賴包
yum -y install wget jq psmisc vim net-tools nfs-utils telnet yum-utils device-mapper-persistent-data lvm2 git network-scripts tar curl -y

# 關閉防火牆與selinux 
systemctl disable --now firewalld 
setenforce 0
sed -i 's#SELINUX=enforcing#SELINUX=disabled#g' /etc/selinux/config

# 關閉交換分區
sed -ri 's/.*swap.*/#&/' /etc/fstab
swapoff -a && sysctl -w vm.swappiness=0
 
cat /etc/fstab
# /dev/mapper/centos-swap swap                    swap    defaults        0 0

# 

# 配置系統句柄数
ulimit -SHn 65535
cat >> /etc/security/limits.conf <<EOF
* soft nofile 655360
* hard nofile 131072
* soft nproc 655350
* hard nproc 655350
* seft memlock unlimited
* hard memlock unlimitedd
EOF


```



```
啟用ipvs

yum install ipvsadm ipset sysstat conntrack libseccomp -y

mkdir -p /etc/modules-load.d/

sudo vim /etc/modules-load.d/ipvs.conf

/etc/modules-load.d/ipvs.conf
------------------------------------------------------------------
ip_vs
ip_vs_rr
ip_vs_wrr
ip_vs_sh
nf_conntrack
ip_tables
ip_set
xt_set
ipt_set
ipt_rpfilter
ipt_REJECT
ipip
------------------------------------------------------------------
 
systemctl restart systemd-modules-load.service



lsmod | grep -e ip_vs -e nf_conntrack
ip_vs_sh               16384  0
ip_vs_wrr              16384  0
ip_vs_rr               16384  0
ip_vs                 180224  6 ip_vs_rr,ip_vs_sh,ip_vs_wrr
nf_conntrack          176128  1 ip_vs
nf_defrag_ipv6         24576  2 nf_conntrack,ip_vs
nf_defrag_ipv4         16384  1 nf_conntrack
libcrc32c              16384  3 nf_conntrack,xfs,ip_vs

```

### 4. 修改k8s.conf

```
sudo vim /etc/sysctl.d/k8s.conf

/etc/sysctl.d/k8s.conf
------------------------------------------------------------------
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
vm.overcommit_memory = 1
vm.panic_on_oom = 0
fs.inotify.max_user_watches = 89100
fs.file-max = 52706963
fs.nr_open = 52706963
net.netfilter.nf_conntrack_max = 2310720
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_max_tw_buckets = 36000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_orphans = 327680
net.ipv4.tcp_orphan_retries = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_timestamps = 0
net.core.somaxconn = 16384
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0
net.ipv6.conf.all.forwarding = 1
------------------------------------------------------------------

modprobe br_netfilter

lsmod |grep conntrack

modprobe ip_conntrack

sysctl -p /etc/sysctl.d/k8s.conf

```


### 5.1 在所有節點安裝containerd

```
### 加載 containerd模塊

cat <<EOF | sudo tee /etc/modules-load.d/containerd.conf
overlay
br_netfilter
EOF

systemctl restart systemd-modules-load.service


cat <<EOF | sudo tee /etc/sysctl.d/99-kubernetes-cri.conf
net.bridge.bridge-nf-call-iptables  = 1
net.ipv4.ip_forward                 = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
 
# 加載内核
 
sysctl --system

查看YUM源中Containerd
# yum list | grep containerd
containerd.io.x86_64                        1.4.12-3.1.el7             docker-ce-stable

下載安裝：

yum install -y containerd.io

```
### 5.2 離線安裝containerd

```
###下載containerd
https://github.com/containerd/containerd/releases/tag/v1.6.4

tar -zxvf containerd-1.6.9-linux-amd64.tar.gz 

cp bin/* /usr/local/bin/

sudo vim /usr/lib/systemd/system/containerd.service


/usr/lib/systemd/system/containerd.service
------------------------------------------------------------------
[Unit]
Description=containerd container runtime
Documentation=https://containerd.io
After=network.target local-fs.target
[Service]
#uncomment to enable the experimental sbservice (sandboxed) version of containerd/cri integration
#Environment="ENABLE_CRI_SANDBOXES=sandboxed"
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/local/bin/containerd
Type=notify
Delegate=yes
KillMode=process
Restart=always
RestartSec=5
# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNPROC=infinity
LimitCORE=infinity
LimitNOFILE=infinity
# Comment TasksMax if your systemd version does not supports it.
# Only systemd 226 and above support this version.
TasksMax=infinity
OOMScoreAdjust=-999
[Install]
WantedBy=multi-user.target
------------------------------------------------------------------

sudo systemctl daemon-reload

sudo systemctl enable --now containerd

sudo systemctl status containerd


###
安裝runc

下載runc
https://github.com/opencontainers/runc/releases/download/v1.1.4/runc.amd64

sudo install -m 755 runc.amd64 /usr/local/sbin/runc

###



###
安裝cni plugins

下載cni plugins
https://github.com/containernetworking/plugins/releases/download/v1.1.1/cni-plugins-linux-amd64-v1.1.1.tgz

sudo mkdir -p /opt/cni/bin

sudo tar Cxzvf /opt/cni/bin cni-plugins-linux-amd64-v1.1.1.tgz

###


###
安裝nerdctl

下載nerdctl
https://github.com/containerd/nerdctl/releases/download/v1.0.0/nerdctl-1.0.0-linux-arm64.tar.gz


sudo cp nerdctl /usr/bin/

###


###
安裝crictl

--------------------------------------------------------------------------------------------------------------------------------
VERSION="v1.25.0"

wget https://github.com/kubernetes-sigs/cri-tools/releases/download/$VERSION/crictl-$VERSION-linux-amd64.tar.gz

sudo tar zxvf crictl-$VERSION-linux-amd64.tar.gz -C /usr/local/bin

sudo rm -f crictl-$VERSION-linux-amd64.tar.gz
---------------------------------------------------------------------------------------------------------------------------------

or

--------------------------------------------------------------------------------------------------------------------------------
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.25.0/crictl-v1.25.0-linux-amd64.tar.gz

sudo tar zxvf crictl-v1.25.0-linux-amd64.tar.gz -C /usr/local/bin

sudo rm -f crictl-v1.25.0-linux-amd64.tar.gz
---------------------------------------------------------------------------------------------------------------------------------

sudo vim /etc/crictl.yaml

/etc/crictl.yaml
-------------------------------------------------------------
runtime-endpoint: unix:///var/run/containerd/containerd.sock
image-endpoint: unix:///var/run/containerd/containerd.sock
timeout: 10
debug: false
-------------------------------------------------------------

###



參考自: https://developer.aliyun.com/article/1100872
```

### 6. 配置containerd的服務

```
生成containerd的配置文件
sudo mkdir /etc/containerd -p 

生成配置文件
containerd config default > /etc/containerd/config.toml

編輯配置文件
sudo vim /etc/containerd/config.toml

/etc/containerd/config.toml
-----
SystemdCgroup = false 改為 SystemdCgroup = true
------

sudo systemctl enable containerd

#Created symlink from /etc/systemd/system/multi-user.target.wants/containerd.service to /usr/lib/systemd/system/containerd.service.

sudo systemctl start containerd
 
 
ctr version
runc -version

```

## 二、部署etcd服務

### 1. 設置簽名證書

```
需下載的資源：
wget https://github.com/cloudflare/cfssl/releases/download/v1.6.1/cfssl_1.6.2_linux_amd64
wget https://github.com/cloudflare/cfssl/releases/download/v1.6.1/cfssljson_1.6.2_linux_amd64
wget https://github.com/cloudflare/cfssl/releases/download/v1.6.1/cfssl-certinfo_1.6.1_linux_amd64

mv cfssl_1.6.1_linux_amd64  /usr/bin/cfssl
mv cfssljson_1.6.1_linux_amd64 /usr/bin/cfssljson
mv cfssl-certinfo_1.6.1_linux_amd64 /usr/bin/cfssl-certinfo
chmod +x /usr/bin/cfssl*

```




### 2. 設置ca.config.json和ca-csr.json
```
mkdir -p ~/TLS/{etcd,k8s}

cd ~/TLS/etcd

自簽CA：

sudo vim ca-config.json

ca-config.json
--------------------------------------------
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "www": {
         "expiry": "87600h",
         "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ]
      }
    }
  }
}
--------------------------------------------

#####

sudo vim ca-csr.json

ca-csr.json
--------------------------------------------
{
    "CN": "etcd CA",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Beijing",
            "ST": "Beijing"
        }
    ]
}
--------------------------------------------


生成證書：
cfssl gencert -initca ca-csr.json | cfssljson -bare ca -

會生成ca.pem和ca-key.pem文件


```




### 3. 設置server-csr.json

```
#使用自簽CA簽發Etcd HTTPS證書

#創建證書申请文件：

sudo vim server-csr.json

server-csr.json
--------------------------------------
{
    "CN": "etcd",
    "hosts": [
    ${master node1 ip},
    ${master node2 ip},
    ${master node3 ip},
    ${worker node1 ip},
    ${worker node2 ip},
    ${worker node3 ip},
    ${worker node4 ip},
    ${worker node5 ip},
    ${other  node1 ip},
    ${other  node2 ip}
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "BeiJing",
            "ST": "BeiJing"
        }
    ]
}
--------------------------------------


#注：上述文件hosts字段中IP為所有etcd節點的集群内部通信IP，一個都不能少！為了方便後期擴容可以多寫幾個預留的IP。
#生成證書：
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=www server-csr.json | cfssljson -bare server

#會生成server.pem和server-key.pem文件。

```


### 4. 安裝etcd配置文件(etcd.conf)


```
1. Etcd 的概念：
Etcd 是一個分布式键值存储系統，Kubernetes使用Etcd進行數據存儲，所以先準備一個Etcd數據庫，為解决Etcd單點故障，應采用集群方式部署，这里使用3台组建集群，可容忍1台機器故障，當然也可以使用5台组建集群，可容忍2台機器故障。

下載地址： https://github.com/etcd-io/etcd/releases

wget https://github.com/etcd-io/etcd/releases/download/v3.5.8/etcd-v3.5.8-linux-amd64.tar.gz

以下在節點master01上操作，為簡化操作，待會將節點master01生成的所有
文件拷貝到節點worker01和節點worker02.



2. 安装配置etcd

mkdir /opt/etcd/{bin,cfg,ssl} -p
tar zxvf etcd-v3.5.8-linux-amd64.tar.gz
mv etcd-v3.5.8-linux-amd64/{etcd,etcdctl} /opt/etcd/bin/





#master01 etcd 配置文件


sudo vim /opt/etcd/cfg/etcd.conf

etcd.conf
---------------------------------------------------------------------------
#[Member]
ETCD_NAME="etcd-1"
ETCD_DATA_DIR="/var/lib/etcd/default.etcd"
ETCD_LISTEN_PEER_URLS="https://${master node1 ip}:2380"
ETCD_LISTEN_CLIENT_URLS="https://${master node1 ip}:2379"
#[Clustering]
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://${master node1 ip}:2380"
ETCD_ADVERTISE_CLIENT_URLS="https://${master node1 ip}:2379"
ETCD_INITIAL_CLUSTER="etcd-1=https://${master node1 ip}:2380,etcd-2=https://${worker01 IP}:2380,etcd-3=https://${worker02 IP}:2380"
ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
ETCD_INITIAL_CLUSTER_STATE="new"
---------------------------------------------------------------------------





###ETCD名詞解釋

ETCD_NAME：節點名稱，集群中唯一
ETCD_DATA_DIR：數據目錄
ETCD_LISTEN_PEER_URLS：集群通信監聽地址
ETCD_LISTEN_CLIENT_URLS：客户端訪問監聽地址
ETCD_INITIAL_ADVERTISE_PEER_URLS：集群通告地址
ETCD_ADVERTISE_CLIENT_URLS：客户端通告地址
ETCD_INITIAL_CLUSTER：集群節點地址
ETCD_INITIAL_CLUSTER_TOKEN：集群Token
ETCD_INITIAL_CLUSTER_STATE：加入集群的當前狀態，new是新集群，existing表示加入已有集群



3. systemd管理etcd

sudo vim /usr/lib/systemd/system/etcd.service

/usr/lib/systemd/system/etcd.service
----------------------------------------------------
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
EnvironmentFile=/opt/etcd/cfg/etcd.conf
ExecStart=/opt/etcd/bin/etcd \
--cert-file=/opt/etcd/ssl/server.pem \
--key-file=/opt/etcd/ssl/server-key.pem \
--peer-cert-file=/opt/etcd/ssl/server.pem \
--peer-key-file=/opt/etcd/ssl/server-key.pem \
--trusted-ca-file=/opt/etcd/ssl/ca.pem \
--peer-trusted-ca-file=/opt/etcd/ssl/ca.pem \
--logger=zap
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
----------------------------------------------------

```
### 2. 安裝etcd

```
#拷貝剛才生成的證書
#把剛才生成的證書拷貝到配置文件中的路徑：
cp ~/TLS/etcd/ca*pem ~/TLS/etcd/server*pem /opt/etcd/ssl/

###同步所有主機
scp -r /opt/etcd/ root@${worker01 IP}:/opt/
scp -r /opt/etcd/ root@${worker02 IP}:/opt/
scp /usr/lib/systemd/system/etcd.service root@${worker01 IP}:/usr/lib/systemd/system/
scp /usr/lib/systemd/system/etcd.service root@${worker02 IP}:/usr/lib/systemd/system/


worker01 etcd 

sudo vim /opt/etcd/cfg/etcd.conf 
------------------------------------------------------------------
#[Member]
ETCD_NAME="etcd-2"
ETCD_DATA_DIR="/var/lib/etcd/default.etcd"
ETCD_LISTEN_PEER_URLS="https://${worker01 IP}:2380"
ETCD_LISTEN_CLIENT_URLS="https://${worker01 IP}:2379"
#[Clustering]
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://${worker01 IP}:2380"
ETCD_ADVERTISE_CLIENT_URLS="https://${worker01 IP}:2379"
ETCD_INITIAL_CLUSTER="etcd-1=https://${master node1 ip}:2380,etcd-2=https://${worker01 IP}:2380,etcd-3=https://${worker02 IP}:2380"
ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
ETCD_INITIAL_CLUSTER_STATE="new"
------------------------------------------------------------------




worker02 etcd 

sudo vim /opt/etcd/cfg/etcd.conf

/opt/etcd/cfg/etcd.conf
---------------------------------------------------------------------
#[Member]
ETCD_NAME="etcd-3"
ETCD_DATA_DIR="/var/lib/etcd/default.etcd"
ETCD_LISTEN_PEER_URLS="https://${worker02 IP}:2380"
ETCD_LISTEN_CLIENT_URLS="https://${worker02 IP}:2379"
#[Clustering]
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://${worker02 IP}:2380"
ETCD_ADVERTISE_CLIENT_URLS="https://${worker02 IP}:2379"
ETCD_INITIAL_CLUSTER="etcd-1=https://${master node1 ip}:2380,etcd-2=https://${worker01 IP}:2380,etcd-3=https://${worker02 IP}:2380"
ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
ETCD_INITIAL_CLUSTER_STATE="new"
---------------------------------------------------------------------


啟動etcd:
sudo systemctl daemon-reload
sudo systemctl start etcd
sudo systemctl enable etcd


驗證：
ETCDCTL_API=3 /opt/etcd/bin/etcdctl --cacert=/opt/etcd/ssl/ca.pem --cert=/opt/etcd/ssl/server.pem --key=/opt/etcd/ssl/server-key.pem --endpoints="https://${master node1 ip}:2379,https://${worker01 IP}:2379,https://${worker02 IP}:2379" endpoint health --write-out=table
```


## 三、部署k8s 1.27.1


### 1. k8s 1.27.1 版本下载

```
1. 從Github下載二進制文件
下載地址： 
https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.27.md
注：打開連接你會發現裡面有很多包，下載一個server包就夠了，包含了Master和Worker Node二進制文件，或是

---------------------------------------------------------------------
wget https://dl.k8s.io/v1.27.1/kubernetes-server-linux-amd64.tar.gz
---------------------------------------------------------------------
```



### 2. 生成k8s 1.27.1 證書(創建ca-config.json & server-csr.json)

```
#創建k8s 的kube-apiserver證書
cd ~/TLS/k8s


sudo vim ca-config.json

ca-config.json
----------------------------------------------
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "kubernetes": {
         "expiry": "87600h",
         "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ]
      }
    }
  }
}
EOF
cat > ca-csr.json << EOF
{
    "CN": "kubernetes",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Beijing",
            "ST": "Beijing",
            "O": "k8s",
            "OU": "System"
        }
    ]
}
----------------------------------------------


生成證書：
cfssl gencert -initca ca-csr.json | cfssljson -bare ca -

會生成ca.pem和ca-key.pem文件。




#使用自簽CA簽發kube-apiserver HTTPS證書
#創建證書申請文件：

sudo vim server-csr.json

server-csr.json
-----------------------------------------------------
{
    "CN": "kubernetes",
    "hosts": [
      "10.0.0.1",
      "127.0.0.1",
      "${master node1 ip}",
      "${worker01 IP}",
      "${worker02 IP}",
      "kubernetes",
      "kubernetes.default",
      "kubernetes.default.svc",
      "kubernetes.default.svc.cluster",
      "kubernetes.default.svc.cluster.local"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "BeiJing",
            "ST": "BeiJing",
            "O": "k8s",
            "OU": "System"
        }
    ]
}
-----------------------------------------------------

#注：上述文件hosts字段中IP為所有Master/LB/VIP IP，一個都不能少！為了方便後期擴容可以多寫幾個預留的IP。

cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes server-csr.json | cfssljson -bare server

#會生成server.pem和server-key.pem文件。

```


### 3. 安裝k8s 1.27.1

### 3.1. 部署k8s 1.27.1

```
#部署 k8s 1.27.1 

#解壓二進制包
mkdir -p /opt/kubernetes/{bin,cfg,ssl,logs} 

tar -zxvf kubernetes-server-linux-amd64.tar

cd kubernetes/server/bin

cp kube-apiserver kube-scheduler kube-controller-manager /opt/kubernetes/bin

cp kubectl /usr/bin/

cp kubectl /usr/local/bin/

```


### 3.2. 部署kube-apiserver(創建kube-apiserver.conf & token.csv & kube-apiserver.service)

```
#部署kube-apiserver
#創建配置文件

sudo vim /opt/kubernetes/cfg/kube-apiserver.conf

/opt/kubernetes/cfg/kube-apiserver.conf
----------------------------------------------------------------------------
KUBE_APISERVER_OPTS="--enable-admission-plugins=NamespaceLifecycle,NodeRestriction,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota \
--v=2 \
--etcd-servers=https://${master node1 ip}:2379,https://${worker01 IP}:2379,https://${worker02 IP}:2379 \
--bind-address=${master node1 ip} \
--secure-port=6443 \
--advertise-address=${master node1 ip} \
--allow-privileged=true \
--service-cluster-ip-range=10.0.0.0/24 \
--authorization-mode=RBAC,Node \
--enable-bootstrap-token-auth=true \
--token-auth-file=/opt/kubernetes/cfg/token.csv \
--service-node-port-range=30000-32767 \
--kubelet-client-certificate=/opt/kubernetes/ssl/server.pem \
--kubelet-client-key=/opt/kubernetes/ssl/server-key.pem \
--tls-cert-file=/opt/kubernetes/ssl/server.pem  \
--tls-private-key-file=/opt/kubernetes/ssl/server-key.pem \
--client-ca-file=/opt/kubernetes/ssl/ca.pem \
--service-account-key-file=/opt/kubernetes/ssl/ca-key.pem \
--service-account-issuer=api \
--service-account-signing-key-file=/opt/kubernetes/ssl/ca-key.pem \
--etcd-cafile=/opt/etcd/ssl/ca.pem \
--etcd-certfile=/opt/etcd/ssl/server.pem \
--etcd-keyfile=/opt/etcd/ssl/server-key.pem \
--requestheader-client-ca-file=/opt/kubernetes/ssl/ca.pem \
--proxy-client-cert-file=/opt/kubernetes/ssl/server.pem \
--proxy-client-key-file=/opt/kubernetes/ssl/server-key.pem \
--requestheader-allowed-names=kubernetes \
--requestheader-extra-headers-prefix=X-Remote-Extra- \
--requestheader-group-headers=X-Remote-Group \
--requestheader-username-headers=X-Remote-User \
--enable-aggregator-routing=true \
--audit-log-maxage=30 \
--audit-log-maxbackup=3 \
--audit-log-maxsize=100 \
--service-account-issuer=https://kubernetes.default.svc.cluster.local \
--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname  \
--audit-log-path=/opt/kubernetes/logs/k8s-audit.log"
----------------------------------------------------------------------------




• ---v：日志等级
• --etcd-servers：etcd集群地址
• --bind-address：監聽地址
• --secure-port：https安全端口
• --advertise-address：集群通告地址
• --allow-privileged：啟用授權
• --service-cluster-ip-range：Service虛擬IP地址段
• --enable-admission-plugins：準入控制模块
• --authorization-mode：認證授權，啟用RBAC授權和節點自管理
• --enable-bootstrap-token-auth：啟用TLS bootstrap機制
• --token-auth-file：bootstrap token文件
• --service-node-port-range：Service nodeport類型默認分配端口範圍
• --kubelet-client-xxx：apiserver訪問kubelet客户端證書
• --tls-xxx-file：apiserver https證書
• 1.20版本必需加的參數：--service-account-issuer，--service-account-signing-key-file
• --etcd-xxxfile：連接Etcd集群證書
• --audit-log-xxx：審計日志
• 啟動聚合層相關配置：--requestheader-client-ca-file，--proxy-client-cert-file，--proxy-client-key-file，--requestheader-allowed-names，--requestheader-extra-headers-prefix，--requestheader-group-headers，--requestheader-username-headers，--enable-aggregator-routing






#拷貝刚才生成的證書
#把剛才生成的證書拷貝到配置文件中的路徑：
cp ~/TLS/k8s/ca*pem ~/TLS/k8s/server*pem /opt/kubernetes/ssl/


#啟用 TLS Bootstrapping 機制
TLS Bootstraping：Master apiserver啟用TLS認證後，Node節點kubelet和
kube-proxy要與kube-apiserver進行通信，必需使用CA簽發的有效證書才可以，
當Node節點很多時，這種客户端證書頒發需要大量工作，同樣也會增加集群擴展複雜度。
為了簡化流程，Kubernetes引入了TLS bootstraping機制来自動頒發客户端證書，
kubelet會以一個低權限用户自動向apiserver申请證書，
kubelet的證書由apiserver動態簽署。
所以強烈建議在Node上使用這種方式，目前主要用於kubelet，kube-proxy
還是由我們統一頒發一個證書。

```
![image](https://github.com/YICHENGSYU/offline-install-k8s-1.27.1/assets/107453333/acd10f5b-282a-4055-8bbf-29e6ce9fcda1)

```

創建上述配置文件中token文件：

sudo vim /opt/kubernetes/cfg/token.csv

/opt/kubernetes/cfg/token.csv
---------------------------------------------------------------------------------------------
33da7da57de05b211fc02e93b655bfbe,kubelet-bootstrap,"system:node-bootstrapper"
---------------------------------------------------------------------------------------------

格式：token，用户名，UID，用户組
token也可自行生成替换：
head -c 16 /dev/urandom | od -An -t x | tr -d ' '




#systemd管理apiserver

sudo vim /usr/lib/systemd/system/kube-apiserver.service

/usr/lib/systemd/system/kube-apiserver.service
---------------------------------------------------------------------------------
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes

[Service]
EnvironmentFile=/opt/kubernetes/cfg/kube-apiserver.conf
ExecStart=/opt/kubernetes/bin/kube-apiserver $KUBE_APISERVER_OPTS
Restart=on-failure

[Install]
WantedBy=multi-user.target
---------------------------------------------------------------------------------


#啟動並設置開機啟動
sudo systemctl daemon-reload

sudo systemctl start kube-apiserver 

sudo systemctl enable kube-apiserver
```


### 3.3. 部署kube-controller-manager(創建kube-controller-manager.conf & kube-controller-manager-csr.json & kube-controller-manager.service)

```
#部署kube-controller-manager
#1. 創建配置文件

sudo vim /opt/kubernetes/cfg/kube-controller-manager.conf


/opt/kubernetes/cfg/kube-controller-manager.conf
----------------------------------------------------------------------------------------
KUBE_CONTROLLER_MANAGER_OPTS=" \
--v=2 \
--leader-elect=true \
--kubeconfig=/opt/kubernetes/cfg/kube-controller-manager.kubeconfig \
--bind-address=127.0.0.1 \
--allocate-node-cidrs=true \
--cluster-cidr=10.244.0.0/16 \
--service-cluster-ip-range=10.0.0.0/24 \
--cluster-signing-cert-file=/opt/kubernetes/ssl/ca.pem \
--cluster-signing-key-file=/opt/kubernetes/ssl/ca-key.pem  \
--root-ca-file=/opt/kubernetes/ssl/ca.pem \
--service-account-private-key-file=/opt/kubernetes/ssl/ca-key.pem \
--cluster-signing-duration=87600h0m0s"
----------------------------------------------------------------------------------------


注:
•--kubeconfig：連接apiserver配置文件
•--leader-elect：當該組件啟動多個時，自動選舉（HA）
•--cluster-signing-cert-file/--cluster-signing-key-file：自動為kubelet頒發證書的CA，與apiserver保持一致


2. 生成kubeconfig文件
生成kube-controller-manager證書：
# 切換工作目錄
cd ~/TLS/k8s

# 創建證書請求文件

sudo vim kube-controller-manager-csr.json

kube-controller-manager-csr.json
-----------------------------------------------------------------------
{
  "CN": "system:kube-controller-manager",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "BeiJing", 
      "ST": "BeiJing",
      "O": "system:masters",
      "OU": "System"
    }
  ]
}
-----------------------------------------------------------------------

# 生成證書
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-controller-manager-csr.json | cfssljson -bare kube-controller-manager


###生成kubeconfig文件（以下是shell命令，直接在终端執行）：

KUBE_CONFIG="/opt/kubernetes/cfg/kube-controller-manager.kubeconfig"

KUBE_APISERVER="https://${master node1 ip}:6443"

sudo kubectl config set-cluster kubernetes --certificateauthority=/opt/kubernetes/ssl/ca.pem --embed-certs=true --server=${KUBE_APISERVER} --kubeconfig=${KUBE_CONFIG}

sudo kubectl config set-credentials kube-controller-manager --client-certificate=./kube-controller-manager.pem --client-key=./kube-controller-manager-key.pem --embed-certs=true --kubeconfig=${KUBE_CONFIG}
  
sudo kubectl config set-context default --cluster=kubernetes --user=kube-controller-manager --kubeconfig=${KUBE_CONFIG}

sudo kubectl config use-context default --kubeconfig=${KUBE_CONFIG}


# systemd管理controller-manager

sudo vim /usr/lib/systemd/system/kube-controller-manager.service

/usr/lib/systemd/system/kube-controller-manager.service
--------------------------------------------------------------------------
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/kubernetes/kubernetes

[Service]
EnvironmentFile=/opt/kubernetes/cfg/kube-controller-manager.conf
ExecStart=/opt/kubernetes/bin/kube-controller-manager \$KUBE_CONTROLLER_MANAGER_OPTS
Restart=on-failure

[Install]
WantedBy=multi-user.target
--------------------------------------------------------------------------


#啟動並設置開機啟動

sudo systemctl daemon-reload

sudo systemctl start kube-controller-manager

sudo systemctl enable kube-controller-manager

```

### 3.4. 部署kube-scheduler(創建kube-scheduler.conf & kube-scheduler-csr.json & kube-scheduler.service)


```
部署kube-scheduler

1. 創建配置文件

sudo vim /opt/kubernetes/cfg/kube-scheduler.conf


/opt/kubernetes/cfg/kube-scheduler.conf
----------------------------------------------------------------------
KUBE_SCHEDULER_OPTS=" \
--v=2 \
--leader-elect \
--kubeconfig=/opt/kubernetes/cfg/kube-scheduler.kubeconfig \
--bind-address=127.0.0.1"
----------------------------------------------------------------------


•--kubeconfig：連接apiserver配置文件
•--leader-elect：當該组件啟動多個時，自動選舉（HA）




#生成kubeconfig文件
生成kube-scheduler證書：

# 切換工作目錄
cd ~/TLS/k8s

# 創建證書請求文件

sudo vim kube-scheduler-csr.json

kube-scheduler-csr.json
---------------------------------------------------------------------------
{
  "CN": "system:kube-scheduler",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "BeiJing",
      "ST": "BeiJing",
      "O": "system:masters",
      "OU": "System"
    }
  ]
}
---------------------------------------------------------------------------

# 生成證書
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-scheduler-csr.json | cfssljson -bare kube-scheduler



生成kubeconfig文件(執行shell指令)：

KUBE_CONFIG="/opt/kubernetes/cfg/kube-scheduler.kubeconfig"

KUBE_APISERVER="https://${master node1 ip}:6443"

sudo kubectl config set-cluster kubernetes --certificate-authority=/opt/kubernetes/ssl/ca.pem --embed-certs=true --server=${KUBE_APISERVER} --kubeconfig=${KUBE_CONFIG}

sudo kubectl config set-credentials kube-scheduler --client-certificate=./kube-scheduler.pem --client-key=./kube-scheduler-key.pem --embed-certs=true --kubeconfig=${KUBE_CONFIG}

sudo kubectl config set-context default --cluster=kubernetes --user=kube-scheduler --kubeconfig=${KUBE_CONFIG}

sudo kubectl config use-context default --kubeconfig=${KUBE_CONFIG}


3. systemd管理scheduler

sudo vim /usr/lib/systemd/system/kube-scheduler.service

/usr/lib/systemd/system/kube-scheduler.service
-----------------------------------------------------------------------
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/kubernetes/kubernetes

[Service]
EnvironmentFile=/opt/kubernetes/cfg/kube-scheduler.conf
ExecStart=/opt/kubernetes/bin/kube-scheduler $KUBE_SCHEDULER_OPTS
Restart=on-failure

[Install]
WantedBy=multi-user.target
-----------------------------------------------------------------------

###啟動並設置開機啟動
sudo systemctl daemon-reload

sudo systemctl start kube-scheduler

sudo systemctl enable kube-scheduler


```

### 3.4. 查看集群狀態(創建admin-csr.json)

```
#查看集群狀態
#生成kubectl連接集群的證書：

cd ~/TLS/k8s
sudo vim admin-csr.json

admin-csr.json
---------------------------------------------------------------
{
  "CN": "admin",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "BeiJing",
      "ST": "BeiJing",
      "O": "system:masters",
      "OU": "System"
    }
  ]
}
---------------------------------------------------------------

cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes admin-csr.json | cfssljson -bare admin



### 生成kubeconfig文件：
mkdir /root/.kube

KUBE_CONFIG="/root/.kube/config"
KUBE_APISERVER="https://${master node1 ip}:6443"

sudo kubectl config set-cluster kubernetes --certificate-authority=/opt/kubernetes/ssl/ca.pem --embed-certs=true --server=${KUBE_APISERVER} --kubeconfig=${KUBE_CONFIG}

sudo kubectl config set-credentials cluster-admin --client-certificate=./admin.pem --client-key=./admin-key.pem --embed-certs=true --kubeconfig=${KUBE_CONFIG}

sudo kubectl config set-context default --cluster=kubernetes --user=cluster-admin --kubeconfig=${KUBE_CONFIG}

sudo kubectl config use-context default --kubeconfig=${KUBE_CONFIG}



### 授權kubelet-bootstrap用户允許请求證書
sudo kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node-bootstrapper --user=kubelet-bootstrap


### 通過kubectl工具查看當前集群组件狀態：

sudo kubectl get cs

NAME                STATUS    MESSAGE             ERROR
scheduler             Healthy   ok                  
controller-manager       Healthy   ok                  
etcd-2               Healthy   {"health":"true"}   
etcd-1               Healthy   {"health":"true"}   
etcd-0               Healthy   {"health":"true"} 

如上輸出說明Master節點組件運行正常。

```

## 四、部署worker節點

### 4.1. 創建工作目錄並拷貝二進制文件

```
在所有worker node創建工作目錄：
mkdir -p /opt/kubernetes/{bin,cfg,ssl,logs} 

從master節點拷貝：

cd /root/software

cd kubernetes/server/bin

cp kubelet kube-proxy /opt/kubernetes/bin   # 本地拷貝

```

### 4.2. 部署kubelet

```
1. 創建配置文件

sudo vim /opt/kubernetes/cfg/kubelet.conf

/opt/kubernetes/cfg/kubelet.conf
----------------------------------------------------------------------
KUBELET_OPTS=" \
--v=2 \
--hostname-override=flyfish81 \
--kubeconfig=/opt/kubernetes/cfg/kubelet.kubeconfig \
--bootstrap-kubeconfig=/opt/kubernetes/cfg/bootstrap.kubeconfig \
--config=/opt/kubernetes/cfg/kubelet-config.yml \
--cert-dir=/opt/kubernetes/ssl \
--runtime-request-timeout=15m  \
--container-runtime-endpoint=unix:///run/containerd/containerd.sock \
--cgroup-driver=systemd \
--node-labels=node.kubernetes.io/node=''"
----------------------------------------------------------------------


#配置參數文件

sudo vim /opt/kubernetes/cfg/kubelet-config.yml


/opt/kubernetes/cfg/kubelet-config.yml
--------------------------------------------------------
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
address: 0.0.0.0
port: 10250
readOnlyPort: 10255
cgroupDriver: cgroupfs
clusterDNS:
- 10.0.0.2
clusterDomain: cluster.local 
failSwapOn: false
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 2m0s
    enabled: true
  x509:
    clientCAFile: /opt/kubernetes/ssl/ca.pem 
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 5m0s
    cacheUnauthorizedTTL: 30s
evictionHard:
  imagefs.available: 15%
  memory.available: 100Mi
  nodefs.available: 10%
  nodefs.inodesFree: 5%
maxOpenFiles: 1000000
maxPods: 110
--------------------------------------------------------


#生成kubelet初次加入集群引導kubeconfig文件
KUBE_CONFIG="/opt/kubernetes/cfg/bootstrap.kubeconfig"

KUBE_APISERVER="https://${master node1 ip}:6443" # apiserver IP:PORT

TOKEN=" 33da7da57de05b211fc02e93b655bfbe" # 与token.csv里保持一致

# 生成 kubelet bootstrap kubeconfig 配置文件

sudo kubectl config set-cluster kubernetes --certificate-authority=/opt/kubernetes/ssl/ca.pem --embed-certs=true --server=${KUBE_APISERVER} --kubeconfig=${KUBE_CONFIG}

sudo kubectl config set-credentials "kubelet-bootstrap" --token=${TOKEN} --kubeconfig=${KUBE_CONFIG}

sudo kubectl config set-context default --cluster=kubernetes --user="kubelet-bootstrap" --kubeconfig=${KUBE_CONFIG}

sudo kubectl config use-context default --kubeconfig=${KUBE_CONFIG}



###systemd管理kubelet

sudo vim /usr/lib/systemd/system/kubelet.service

/usr/lib/systemd/system/kubelet.service
----------------------------------------------------------
[Unit]
Description=Kubernetes Kubelet
After=docker.service

[Service]
EnvironmentFile=/opt/kubernetes/cfg/kubelet.conf
ExecStart=/opt/kubernetes/bin/kubelet $KUBELET_OPTS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
----------------------------------------------------------


啟動並設置開機啟動
sudo systemctl daemon-reload
sudo systemctl start kubelet
sudo systemctl enable kubelet



批準kubelet證書申请並加入集群
# 查看kubelet證書请求
kubectl get csr
[t27020@worker01]# kubectl get csr
NAME                                                   AGE     SIGNERNAME                                    REQUESTOR           REQUESTEDDURATION   CONDITION
node-csr-hWj6tp2sY8FcUBVyzLJrQ3W0OLrAkph0IkZYhfD5xbk   3m25s   kubernetes.io/kube-apiserver-client-kubelet   kubelet-bootstrap   <none>              Pending


# 批準申请
kubectl certificate approve node-csr-hWj6tp2sY8FcUBVyzLJrQ3W0OLrAkph0IkZYhfD5xbk

# 查看節點

[t27020@worker01]# sudo kubectl get node
NAME        STATUS     ROLES    AGE   VERSION
mater01   NotReady   <none>   5s    v1.27.1

```



### 4.3. 部署kube-proxy

```
1. 創建配置文件

sudo vim /opt/kubernetes/cfg/kube-proxy.conf

/opt/kubernetes/cfg/kube-proxy.conf
----------------------------------------------------------
KUBE_PROXY_OPTS=" \
--v=2 \
--config=/opt/kubernetes/cfg/kube-proxy-config.yml"
----------------------------------------------------------

2. 配置參數文件

sudo vim /opt/kubernetes/cfg/kube-proxy-config.yml

/opt/kubernetes/cfg/kube-proxy-config.yml
-----------------------------------------------------------
kind: KubeProxyConfiguration
apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: 0.0.0.0
metricsBindAddress: 0.0.0.0:10249
clientConnection:
  kubeconfig: /opt/kubernetes/cfg/kube-proxy.kubeconfig
hostnameOverride: master01
clusterCIDR: 10.244.0.0/16
mode: ipvs
ipvs:
  scheduler: "rr"
iptables:
  masqueradeAll: true
-----------------------------------------------------------


2. 配置參數文件

sudo vim /opt/kubernetes/cfg/kube-proxy-config.yml

/opt/kubernetes/cfg/kube-proxy-config.yml
---------------------------------------------------------------
kind: KubeProxyConfiguration
apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: 0.0.0.0
metricsBindAddress: 0.0.0.0:10249
clientConnection:
  kubeconfig: /opt/kubernetes/cfg/kube-proxy.kubeconfig
hostnameOverride: flyfish81
clusterCIDR: 10.244.0.0/16
mode: ipvs
ipvs:
  scheduler: "rr"
iptables:
  masqueradeAll: true
---------------------------------------------------------------


#生成kube-proxy.kubeconfig文件

# 切換工作目錄
cd ~/TLS/k8s

# 創建證書請求文件

sudo vim kube-proxy-csr.json

kube-proxy-csr.json
-------------------------------------
{
  "CN": "system:kube-proxy",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "BeiJing",
      "ST": "BeiJing",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
-------------------------------------


# 生成證書
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-proxy-csr.json | cfssljson -bare kube-proxy

生成kubeconfig文件(執行shel指令)：

KUBE_CONFIG="/opt/kubernetes/cfg/kube-proxy.kubeconfig"

KUBE_APISERVER="https://${master node1 ip}:6443"

kubectl config set-cluster kubernetes --certificate-authority=/opt/kubernetes/ssl/ca.pem --embed-certs=true --server=${KUBE_APISERVER} --kubeconfig=${KUBE_CONFIG}

kubectl config set-credentials kube-proxy --client-certificate=./kube-proxy.pem --client-key=./kube-proxy-key.pem --embed-certs=true --kubeconfig=${KUBE_CONFIG}

kubectl config set-context default --cluster=kubernetes --user=kube-proxy --kubeconfig=${KUBE_CONFIG}

sudo kubectl config use-context default --kubeconfig=${KUBE_CONFIG}


###systemd管理kube-proxy

sudo vim /usr/lib/systemd/system/kube-proxy.service

/usr/lib/systemd/system/kube-proxy.service
---------------------------------------------------------------
[Unit]
Description=Kubernetes Proxy
After=network.target

[Service]
EnvironmentFile=/opt/kubernetes/cfg/kube-proxy.conf
ExecStart=/opt/kubernetes/bin/kube-proxy $KUBE_PROXY_OPTS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
---------------------------------------------------------------

###啟動並設置開機啟動

sudo systemctl daemon-reload

sudo systemctl start kube-proxy

sudo systemctl enable kube-proxy

```

## 五、部署網絡組件(calico或flannel擇一)

### 部署網絡組件(calico)

```
網絡組件有很多種，只需要部署其中一個即可，Calico性能較好且能進行更詳細的配置。

Calico是一個純三層的數據中心網絡方案，Calico支持廣泛的平台，包括Kubernetes、OpenStack等。

Calico 在每一個計算節點利用 Linux Kernel 實現了一个高效的虛擬路由器（ vRouter） 来負責數據轉發，而每個 vRouter 通過 BGP 協議負責把自己上運行的 workload 的路由信息向整個 Calico 網絡内傳播。

此外，Calico 項目還實現了 Kubernetes 網絡策略，提供ACL功能。

1.下載Calico

wget https://docs.tigera.io/archive/v3.25/manifests/calico.yaml

更改calico.yaml配置(有查到資料說calico會自動mapping到正確的IP，但為了保險起見還是需要更改IP)

sudo vim calico.yaml

calico.yaml
---------------------------------
- name: CALICO_IPV4POOL_CIDR
  value: "10.244.0.0/16"
---------------------------------

sudo kubectl apply -f calico.yaml

sudo kubectl get pod -n kube-system

sudo kubectl get node


### 授權apiserver訪問kubelet
應用場景：例如kubectl logs


sudo vim apiserver-to-kubelet-rbac.yaml


apiserver-to-kubelet-rbac.yaml
--------------------------------------------------------------------------
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:kube-apiserver-to-kubelet
rules:
  - apiGroups:
      - ""
    resources:
      - nodes/proxy
      - nodes/stats
      - nodes/log
      - nodes/spec
      - nodes/metrics
      - pods/log
    verbs:
      - "*"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system:kube-apiserver
  namespace: ""
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:kube-apiserver-to-kubelet
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: kubernetes
--------------------------------------------------------------------------

sudo kubectl apply -f apiserver-to-kubelet-rbac.yaml

```

### 部署網絡組件(flannel)

```
flannel也是網絡組件的一種，是最受歡迎且最簡單的一種網絡組件
wget https://github.com/flannel-io/flannel/releases/download/v0.22.2/kube-flannel.yml

sudo kubectl apply -f kube-flannel.yml

sudo kubectl get nodes

```

## 六、新增一個worker node

### 1. 同步配置文件

```
1. 拷貝已部署好的Node相關文件到新節點
在Master節點將Worker Node涉及文件拷貝到新節點${worker node03 IP}/${worker node04 IP}

scp -r /opt/kubernetes root@${worker node03 IP}:/opt/

scp /opt/kubernetes/ssl/ca.pem root@${worker node03 IP}:/opt/kubernetes/ssl

scp -r /usr/lib/systemd/system/{kubelet,kube-proxy}.service root@${worker node03 IP}:/usr/lib/systemd/system

scp -r /opt/kubernetes root@${worker node04 IP}:/opt/

scp /opt/kubernetes/ssl/ca.pem root@${worker node04 IP}:/opt/kubernetes/ssl

scp -r /usr/lib/systemd/system/{kubelet,kube-proxy}.service root@${worker node04 IP}:/usr/lib/systemd/system


####### 在worker node 3 & worker node 4 ###########

删除kubelet證書和kubeconfig文件
rm -rf /opt/kubernetes/cfg/kubelet.kubeconfig 
rm -rf /opt/kubernetes/ssl/kubelet*
rm -rf /opt/kubernetes/logs/*

注：這幾個文件是證書申請審批後自動生成的，每個Node不同，必需删除



###### 在worker node 3 ########## 

修改主機名 [改節點的主機名]
worker node 3 :

sudo vim /opt/kubernetes/cfg/kubelet.conf
--hostname-override=worker03

sudo vim /opt/kubernetes/cfg/kube-proxy-config.yml
hostnameOverride: worker03



###### 在worker node 4 ########## 

修改主機名 [改節點的主機名]
worker node 4 :

sudo vim /opt/kubernetes/cfg/kubelet.conf
--hostname-override=worker04

sudo vim /opt/kubernetes/cfg/kube-proxy-config.yml
hostnameOverride: worker04


####### 在worker node 3 & worker node 4 ###########

啟動並設置開機啟動

sudo systemctl daemon-reload

sudo systemctl start kubelet kube-proxy

sudo systemctl enable kubelet kube-proxy


####### 在master node 1上 ###########

在Master上批準新Node kubelet證書申請

sudo kubectl get csr

# 授權 worker node 請求
sudo kubectl certificate approve node-csr-4aVtcOsvmkhKQ1dnyJAOMD3VDcORfXulPs9Xn8d-QIE

sudo kubectl certificate approve node-csr-9dAHpoiTUPrG4nY-kfJD_Cir2wnWLfuYT004MVr53uw

sudo kubectl get pod -n kube-system 

sudo kubectl get node
```

## 七、 部署Dashboard和CoreDNS

### 1. 部署Dashboard
```
github:
https://github.com/kubernetes/dashboard/releases/tag/v2.7.0

wget https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml
目前最新版本v2.7.0 

修改recommended.yaml

sudo vim recommended.yaml

recommended.yaml
------------------------------------------
spec:
  ports:
    - port: 443
      targetPort: 8443
      nodePort: 30001
  type: NodePort
  selector:
    k8s-app: kubernetes-dashboard
------------------------------------------

sudo kubectl apply -f recommended.yaml

sudo kubectl get pods -n kubernetes-dashboard

sudo kubectl get pods,svc -n kubernetes-dashboard


#######創建service account並绑定默認cluster-admin管理員集群角色：

sudo vim dashadmin.yaml

dashadmin.yaml
------------------------------------------------------
-----
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kubernetes-dashboard

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-user
  namespace: kubernetes-dashboard
-----
------------------------------------------------------
sudo kubectl apply -f dashadmin.yaml

創建用户登錄token

sudo kubectl -n kubernetes-dashboard create token admin-user
-------------------------------------------------------------------------
${admin-user token}
-------------------------------------------------------------------------

打開web

https://${master node1 ip}:30001

填入獲得的admin-user token

```

### 2. 部署CoreDNS

```
創建 coredns.yaml

sudo vim coredns.yaml

coredns.yaml
--------------------------------------------------------------------------
# __MACHINE_GENERATED_WARNING__

apiVersion: v1
kind: ServiceAccount
metadata:
  name: coredns
  namespace: kube-system
  labels:
      kubernetes.io/cluster-service: "true"
      addonmanager.kubernetes.io/mode: Reconcile
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
    addonmanager.kubernetes.io/mode: Reconcile
  name: system:coredns
rules:
- apiGroups:
  - ""
  resources:
  - endpoints
  - services
  - pods
  - namespaces
  verbs:
  - list
  - watch
- apiGroups:
  - ""
  resources:
  - nodes
  verbs:
  - get
- apiGroups:
  - discovery.k8s.io
  resources:
  - endpointslices
  verbs:
  - list
  - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
    addonmanager.kubernetes.io/mode: EnsureExists
  name: system:coredns
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:coredns
subjects:
- kind: ServiceAccount
  name: coredns
  namespace: kube-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
  labels:
      addonmanager.kubernetes.io/mode: EnsureExists
data:
  Corefile: |
    .:53 {
        errors
        health {
            lameduck 5s
        }
        ready
        kubernetes __DNS__DOMAIN__ in-addr.arpa ip6.arpa {
            pods insecure
            fallthrough in-addr.arpa ip6.arpa
            ttl 30
        }
        prometheus :9153
        forward . /etc/resolv.conf {
            max_concurrent 1000
        }
        cache 30
        loop
        reload
        loadbalance
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coredns
  namespace: kube-system
  labels:
    k8s-app: kube-dns
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
    kubernetes.io/name: "CoreDNS"
spec:
  # replicas: not specified here:
  # 1. In order to make Addon Manager do not reconcile this replicas parameter.
  # 2. Default is 1.
  # 3. Will be tuned in real time if DNS horizontal auto-scaling is turned on.
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  selector:
    matchLabels:
      k8s-app: kube-dns
  template:
    metadata:
      labels:
        k8s-app: kube-dns
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      priorityClassName: system-cluster-critical
      serviceAccountName: coredns
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                  - key: k8s-app
                    operator: In
                    values: ["kube-dns"]
              topologyKey: kubernetes.io/hostname
      tolerations:
        - key: "CriticalAddonsOnly"
          operator: "Exists"
      nodeSelector:
        kubernetes.io/os: linux
      containers:
      - name: coredns
        image: registry.k8s.io/coredns/coredns:v1.10.1
        imagePullPolicy: IfNotPresent
        resources:
          limits:
            memory: __DNS__MEMORY__LIMIT__
          requests:
            cpu: 100m
            memory: 70Mi
        args: [ "-conf", "/etc/coredns/Corefile" ]
        volumeMounts:
        - name: config-volume
          mountPath: /etc/coredns
          readOnly: true
        ports:
        - containerPort: 53
          name: dns
          protocol: UDP
        - containerPort: 53
          name: dns-tcp
          protocol: TCP
        - containerPort: 9153
          name: metrics
          protocol: TCP
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 60
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 5
        readinessProbe:
          httpGet:
            path: /ready
            port: 8181
            scheme: HTTP
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            add:
            - NET_BIND_SERVICE
            drop:
            - all
          readOnlyRootFilesystem: true
      dnsPolicy: Default
      volumes:
        - name: config-volume
          configMap:
            name: coredns
            items:
            - key: Corefile
              path: Corefile
---
apiVersion: v1
kind: Service
metadata:
  name: kube-dns
  namespace: kube-system
  annotations:
    prometheus.io/port: "9153"
    prometheus.io/scrape: "true"
  labels:
    k8s-app: kube-dns
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
    kubernetes.io/name: "CoreDNS"
spec:
  selector:
    k8s-app: kube-dns
  clusterIP: __DNS__SERVER__
  ports:
  - name: dns
    port: 53
    protocol: UDP
  - name: dns-tcp
    port: 53
    protocol: TCP
  - name: metrics
    port: 9153
    protocol: TCP
--------------------------------------------------------------------------

sudo kubectl apply -f coredns.yaml

#### 測試:
  sudo kubectl run -it --rm dns-test --image=busybox:1.28.4 sh
  
### 創建一個nginx pod 測試：
sudo kubectl create deployment nginx --image=nginx:1.25

sudo kubectl expose deployment nginx --port=80 --type=NodePort

sudo kubectl get deploy,svc,pod
  
  
#### 確認nginx是否成功運作  
curl  http://${master node1 ip}:${nginx port(30000開頭)}
```


## **注一 : kubelet安裝於master node 上**

```
###

    參考的教程裡沒有在master node上安裝kubelet，如果有需要可以在master node上安裝kubelet，
    在master node上部署服務，可參考 四、部署worker節點的 4.2部署kubelet和4.3部署kube-proxy，
    對master node進行部署。

###
```


## **注二 : 附上壓縮後的image檔和配置檔**

### tar file與image對照表

| tar name                         |image name|
|:---------------------------------|:--------:| 
| aliGoogleContainersPause.tar     |  registry.aliyuncs.com/google_containers/pause:3.7   |
| busybox.tar                      |   busybox:1.28.4   |
| calicoCni325.tar                 |   calico/cni:v3.25.0   |
| calicoKubeControllers325.tar     |   calico/kube-controllers:v3.25.0   |
| calicoNode325.tar                |   calico/node:v3.25.0   |
| coredns.tar                      |   coredns/coredns:1.10.1, v1.10.1   |
| flannel.tar                      |   flannel/flannel:v0.22.2   |
| flannelCni.tar                   |   flannel/flannel-cni-plugin:v1.2.0   |
| dashboard.tar                    |   kubernetesui/dashboard:v2.7.0   |
| metricScraper.tar                |   kubernetesui/metrics-scraper:v1.0.8   |
| nginx.tar                        |   nginx:1.25   |

### 將tar file經過scp 複製到vm上後，需要使用以下指令還原image

```
sudo ctr --namespace=k8s.io images import ${tar file name}.tar

舉例如下 : 
sudo ctr --namespace=k8s.io images import dashboard.tar

注 : 因為containerd有namespace的概念，所以需要將image還原至k8s.io namespace下，
k8s才能讀取到image，進而建立pods
```

