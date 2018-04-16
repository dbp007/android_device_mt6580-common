/*
 * Copyright 2018, The LineageOS Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 *
 *     http://www.apache.org/licenses/LICENSE-2.0 
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/route.h>
#include <linux/ipv6_route.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/un.h>

#include "netutils/ifc.h"

#include <cutils/log.h>
#include <cutils/properties.h>

#undef LOG_TAG
#define LOG_TAG "NetUtils-MTK"
#define SIOCKILLSOCK 0x893a // MTK
#define DBG 0
#define INET_ADDRLEN 4
#define INET6_ADDRLEN 16
#define SIOCSTXQSTATE (SIOCDEVPRIVATE + 0)  //start/stop ccmni tx queue
#define SIOCSCCMNICFG (SIOCDEVPRIVATE + 1)  //configure ccmni/md remapping

static int ifc_ctl_sock = -1;
static int ifc_ctl_sock6 = -1;
static pthread_mutex_t ifc_sock_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_mutex_t ifc_sock6_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
void printerr(char *fmt, ...);

struct uid_err {
    int appuid;
	int errorNum;
};

int ifc_init(void)
{
    int ret;

    pthread_mutex_lock(&ifc_sock_mutex);
    if (ifc_ctl_sock == -1) {
        ifc_ctl_sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (ifc_ctl_sock < 0) {
            printerr("socket() failed: %s\n", strerror(errno));
        }
    }

    ret = ifc_ctl_sock < 0 ? -1 : 0;
    if (DBG) printerr("ifc_init_returning %d", ret);
    return ret;
}

static void ifc_init_ifr(const char *name, struct ifreq *ifr)
{
    memset(ifr, 0, sizeof(struct ifreq));
    strlcpy(ifr->ifr_name, name, IFNAMSIZ);
}


static int ifc_set_flags(const char *name, unsigned set, unsigned clr)
{
    struct ifreq ifr;
    ifc_init_ifr(name, &ifr);

    if(ioctl(ifc_ctl_sock, SIOCGIFFLAGS, &ifr) < 0) return -1;
    ifr.ifr_flags = (ifr.ifr_flags & (~clr)) | set;
    return ioctl(ifc_ctl_sock, SIOCSIFFLAGS, &ifr);
}

/* MTK bits*/
extern int ifc_reset_connection_by_uid(int uid, int error) {

    int tcp_ctl_sock;
    int result = -1;
    struct uid_err uid_e;

    uid_e.appuid = uid;
    uid_e.errorNum = error;

    tcp_ctl_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_ctl_sock < 0) {
        printerr("socket() failed: %s\n", strerror(errno));
        return -1;
    }

    if(uid_e.appuid < 0){
        ALOGE("ifc_reset_connection_by_uid, invalide uid: %d", uid_e.appuid);
        close(tcp_ctl_sock);
        return -1;
    }

    ALOGD("ifc_reset_connection_by_uid, appuid = %d, error = %d ",
              uid_e.appuid, uid_e.errorNum);
    result = ioctl(tcp_ctl_sock, SIOCKILLSOCK, &uid_e);
    if(result < 0)
        ALOGE("ifc_reset_connection_by_uid, result= %d, error =%s ", result, strerror(errno));

        close(tcp_ctl_sock);
    ALOGD("ifc_reset_connection_by_uid, result= %d ",result);

    return result;
}

extern int ifc_enable_allmc(const char *ifname) {
    
    int result;

    ifc_init();
    result = ifc_set_flags(ifname, IFF_ALLMULTI, 0);
    ifc_close();

    ALOGD("ifc_enable_allmc(%s) = %d", ifname, result);
    
    return result;
}

extern int ifc_disable_allmc(const char *ifname) {

    int result;

    ifc_init();
    result = ifc_set_flags(ifname, 0, IFF_ALLMULTI);
    ifc_close();

    ALOGD("ifc_disable_allmc(%s) = %d", ifname, result);
    return result;
}
extern int ifc_is_up(const char *name, unsigned *isup) {
    struct ifreq ifr;
    ifc_init_ifr(name, &ifr);

    if(ioctl(ifc_ctl_sock, SIOCGIFFLAGS, &ifr) < 0) {
        printerr("ifc_is_up get flags error:%d(%s)", errno, strerror(errno));
        return -1;
    }
    if(ifr.ifr_flags & IFF_UP)
        *isup = 1;
    else
        *isup = 0;

    return 0;
}

static int ifc_netd_sock_init(void) {
    int ifc_netd_sock;
    const int one = 1;
    struct sockaddr_un netd_addr;

        ifc_netd_sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (ifc_netd_sock < 0) {
            printerr("ifc_netd_sock_init: create socket failed");
            return -1;
        }

        setsockopt(ifc_netd_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        memset(&netd_addr, 0, sizeof(netd_addr));
        netd_addr.sun_family = AF_UNIX;
        strlcpy(netd_addr.sun_path, "/dev/socket/netd",
            sizeof(netd_addr.sun_path));
        if (TEMP_FAILURE_RETRY(connect(ifc_netd_sock,
                     (const struct sockaddr*) &netd_addr,
                     sizeof(netd_addr))) != 0) {
            printerr("ifc_netd_sock_init: connect to netd failed, fd=%d, err: %d(%s)",
                ifc_netd_sock, errno, strerror(errno));
            close(ifc_netd_sock);
            return -1;
        }

    if (DBG) printerr("ifc_netd_sock_init fd=%d", ifc_netd_sock);
    return ifc_netd_sock;
}

/*do not call this function in netd*/
extern int ifc_set_throttle(const char *ifname, int rxKbps, int txKbps) {
    FILE* fnetd = NULL;
    int ret = -1;
    int seq = 1;
    char rcv_buf[24];
    int nread = 0;
    int netd_sock = 0;

    ALOGD("enter ifc_set_throttle: ifname = %s, rx = %d kbs, tx = %d kbs", ifname, rxKbps, txKbps);

    netd_sock = ifc_netd_sock_init();
    if(netd_sock <= 0)
        goto exit;

    // Send the request.
    fnetd = fdopen(netd_sock, "r+");
    if(fnetd == NULL){
        ALOGE("open netd socket failed, err:%d(%s)", errno, strerror(errno));
        goto exit;
    }
    if (fprintf(fnetd, "%d interface setthrottle %s %d %d", seq, ifname, rxKbps, txKbps) < 0) {
        goto exit;
    }
    // literal NULL byte at end, required by FrameworkListener
    if (fputc(0, fnetd) == EOF ||
        fflush(fnetd) != 0) {
        goto exit;
    }
    ret = 0;

    //Todo: read the whole response from netd
    nread = fread(rcv_buf, 1, 20, fnetd);
    rcv_buf[23] = 0;
    ALOGD("response: %s", rcv_buf);
exit:
    if (fnetd != NULL) {
        fclose(fnetd);
    }
    return ret;
}

/*do not call this function in netd*/
extern int ifc_set_fwmark_rule(const char *ifname, int mark, int add) {
    FILE* fnetd = NULL;
    int ret = -1;
    int seq = 2;
    char rcv_buf[24];
      int nread = 0;
      const char* op;
    int netd_sock = 0;

    if (add) {
        op = "add";
    } else {
        op = "remove";
    }
    ALOGD("enter ifc_set_fwmark_rule: ifname = %s, mark = %d, op = %s", ifname, mark, op);

    netd_sock = ifc_netd_sock_init();
    if(netd_sock <= 0)
        goto exit;

    // Send the request.
    fnetd = fdopen(netd_sock, "r+");
    if(fnetd == NULL){
        ALOGE("open netd socket failed, err:%d(%s)", errno, strerror(errno));
        goto exit;
    }
    if (fprintf(fnetd, "%d network fwmark %s %s %d", seq, op, ifname, mark) < 0) {
        goto exit;
    }
    // literal NULL byte at end, required by FrameworkListener
    if (fputc(0, fnetd) == EOF ||
        fflush(fnetd) != 0) {
        goto exit;
    }
    ret = 0;

    //Todo: read the whole response from netd
    nread = fread(rcv_buf, 1, 20, fnetd);
    rcv_buf[23] = 0;
    ALOGD("ifc_set_fwmark_rule response: %s", rcv_buf);
exit:
    if (fnetd != NULL) {
        fclose(fnetd);
    }
    return ret;
}

extern int ifc_set_txq_state(const char *ifname, int state) {
    struct ifreq ifr;
    int ret, ctl_sock;

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;
    ifr.ifr_ifru.ifru_ivalue = state;

    ctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(ctl_sock < 0){
        ALOGE("create ctl socket failed\n");
        return -1;
    }
    ret = ioctl(ctl_sock, SIOCSTXQSTATE, &ifr);
    if(ret < 0)
        ALOGE("ifc_set_txq_state failed, err:%d(%s)\n", errno, strerror(errno));
    else
        ALOGI("ifc_set_txq_state as %d, ret: %d\n", state, ret);

    close(ctl_sock);

    return ret;
}

extern int ifc_ccmni_md_cfg(const char *ifname, int md_id) {
    struct ifreq ifr;
    int ret = 0;
    int ctl_sock = 0;

    ifc_init_ifr(ifname, &ifr);
    ifr.ifr_ifru.ifru_ivalue = md_id;

    ctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(ctl_sock < 0){
        printerr("ifc_ccmni_md_cfg: create ctl socket failed\n");
        return -1;
    }

    if(ioctl(ctl_sock, SIOCSCCMNICFG, &ifr) < 0) {
        printerr("ifc_ccmni_md_configure(ifname=%s, md_id=%d) error:%d(%s)", \
            ifname, md_id, errno, strerror(errno));
        ret = -1;
    } else {
        printerr("ifc_ccmni_md_configure(ifname=%s, md_id=%d) OK", ifname, md_id);
    }

    close(ctl_sock);
    return ret;
}

